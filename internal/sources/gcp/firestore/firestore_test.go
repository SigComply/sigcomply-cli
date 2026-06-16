package firestore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	firestore "google.golang.org/api/firestore/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call count to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	databases []*firestore.GoogleFirestoreAdminV1Database
	listErr   error
	calls     int
	project   string
}

func (f *fakeAPI) ListDatabases(_ context.Context, project string) ([]*firestore.GoogleFirestoreAdminV1Database, error) {
	f.calls++
	f.project = project
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.databases, nil
}

func fsReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) databasePayload {
	t.Helper()
	var p databasePayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.firestore" {
		t.Errorf("ID = %q; want gcp.firestore", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "nosql_table" {
		t.Errorf("Emits = %v; want [nosql_table]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SortsAndPopulates covers the happy path: a hardened database
// (CMEK key, PITR on, deletion protection on) and an open default database
// (Google-managed keys, PITR disabled, deletion protection unspecified)
// emit two records sorted by ID with every field mapped. encryption_enabled
// is always true regardless of CMEK.
func TestCollect_SortsAndPopulates(t *testing.T) {
	fake := &fakeAPI{
		databases: []*firestore.GoogleFirestoreAdminV1Database{
			{ // open default database, sorts second by Name.
				Name:                          "projects/p/databases/(default)",
				LocationId:                    "nam5",
				Type:                          "FIRESTORE_NATIVE",
				PointInTimeRecoveryEnablement: "POINT_IN_TIME_RECOVERY_DISABLED",
				DeleteProtectionState:         "DELETE_PROTECTION_STATE_UNSPECIFIED",
			},
			{ // hardened named database, sorts first by Name.
				Name:                          "projects/p/databases/analytics",
				LocationId:                    "us-central1",
				Type:                          "FIRESTORE_NATIVE",
				PointInTimeRecoveryEnablement: "POINT_IN_TIME_RECOVERY_ENABLED",
				DeleteProtectionState:         "DELETE_PROTECTION_ENABLED",
				CmekConfig: &firestore.GoogleFirestoreAdminV1CmekConfig{
					KmsKeyName: "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k",
				},
			},
		},
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), fsReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID (full resource name): ".../databases/(default)" sorts
	// before ".../databases/analytics" ('(' is ASCII 40, 'a' is 97).
	if n0, n1 := decodePayload(t, &records[0]).Name, decodePayload(t, &records[1]).Name; n0 != "(default)" || n1 != "analytics" {
		t.Fatalf("order = %q,%q; want (default) before analytics", n0, n1)
	}
	for i := range records {
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (databases have no identity)", i, records[i].IdentityKey)
		}
	}

	wantHardened := databasePayload{
		ID:   "projects/p/databases/analytics",
		Name: "analytics", Provider: "gcp",
		EncryptionEnabled: true, PointInTimeRecoveryEnabled: true, DeletionProtection: true,
		Location: "us-central1", DatabaseType: "FIRESTORE_NATIVE",
		IsCustomerManaged:       true,
		KMSKeyName:              "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k",
		PITRState:               "POINT_IN_TIME_RECOVERY_ENABLED",
		DeletionProtectionState: "DELETE_PROTECTION_ENABLED",
	}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantHardened) {
		t.Errorf("hardened payload = %+v; want %+v", got, wantHardened)
	}

	wantOpen := databasePayload{
		ID:   "projects/p/databases/(default)",
		Name: "(default)", Provider: "gcp",
		EncryptionEnabled: true, PointInTimeRecoveryEnabled: false, DeletionProtection: false,
		Location: "nam5", DatabaseType: "FIRESTORE_NATIVE",
		PITRState:               "POINT_IN_TIME_RECOVERY_DISABLED",
		DeletionProtectionState: "DELETE_PROTECTION_STATE_UNSPECIFIED",
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantOpen) {
		t.Errorf("open payload = %+v; want %+v", got, wantOpen)
	}
}

// TestBuildPayload_BareDatabase verifies a database with no CMEK / PITR /
// deletion-protection config maps to honest false values (encryption_enabled
// stays true — Firestore always encrypts) and leaves the customer-managed
// extras empty.
func TestBuildPayload_BareDatabase(t *testing.T) {
	got := buildPayload(&firestore.GoogleFirestoreAdminV1Database{Name: "projects/p/databases/(default)"})
	if got.ID != "projects/p/databases/(default)" || got.Name != "(default)" {
		t.Errorf("id/name = %q/%q; want full-name / (default)", got.ID, got.Name)
	}
	if !got.EncryptionEnabled {
		t.Error("encryption_enabled should always be true (Firestore always encrypts at rest)")
	}
	if got.PointInTimeRecoveryEnabled || got.DeletionProtection || got.IsCustomerManaged {
		t.Errorf("bare database should map to false: %+v", got)
	}
	if got.KMSKeyName != "" {
		t.Errorf("bare database should leave kms_key_name empty: %+v", got)
	}
}

// TestDatabaseShortName covers the trailing-id parse, including the
// "(default)" literal and the fallback when "/databases/" is absent.
func TestDatabaseShortName(t *testing.T) {
	cases := map[string]string{
		"projects/p/databases/(default)": "(default)",
		"projects/p/databases/analytics": "analytics",
		"analytics":                      "analytics",
		"":                               ".",
	}
	for in, want := range cases {
		if got := databaseShortName(in); got != want {
			t.Errorf("databaseShortName(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestCollect_NilDatabaseSkipped(t *testing.T) {
	fake := &fakeAPI{databases: []*firestore.GoogleFirestoreAdminV1Database{nil, {Name: "projects/p/databases/real"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), fsReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil database skipped)", len(records))
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"kms_key"}})
	if err == nil {
		t.Fatal("want error for unaccepted type; got nil")
	}
}

func TestCollect_PropagatesListError(t *testing.T) {
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{listErr: wantErr}})
	_, err := p.Collect(context.Background(), fsReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{databases: []*firestore.GoogleFirestoreAdminV1Database{{Name: "projects/p/databases/d"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), fsReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

// TestRealFirestore_ListDatabases exercises the production adapter against
// an httptest server, verifying it lists databases in one call.
func TestRealFirestore_ListDatabases(t *testing.T) {
	body := mustMarshal(t, firestore.GoogleFirestoreAdminV1ListDatabasesResponse{
		Databases: []*firestore.GoogleFirestoreAdminV1Database{
			{Name: "projects/p/databases/(default)"},
			{Name: "projects/p/databases/analytics"},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realFirestore{svc: newTestService(t, srv)}
	databases, err := r.ListDatabases(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListDatabases: %v", err)
	}
	if len(databases) != 2 {
		t.Fatalf("len = %d; want 2", len(databases))
	}
}

// TestRealFirestore_UnreachableErrors verifies the adapter refuses a
// partial result: any unreachable location is an error, not a silent drop.
func TestRealFirestore_UnreachableErrors(t *testing.T) {
	body := mustMarshal(t, firestore.GoogleFirestoreAdminV1ListDatabasesResponse{
		Databases:   []*firestore.GoogleFirestoreAdminV1Database{{Name: "projects/p/databases/(default)"}},
		Unreachable: []string{"eur3"},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realFirestore{svc: newTestService(t, srv)}
	if _, err := r.ListDatabases(context.Background(), "p"); err == nil {
		t.Fatal("want error when a location is unreachable; got nil")
	}
}

// TestRealFirestore_Error verifies the adapter surfaces HTTP errors.
func TestRealFirestore_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	r := &realFirestore{svc: newTestService(t, srv)}
	if _, err := r.ListDatabases(context.Background(), "p"); err == nil {
		t.Fatal("want error from 403; got nil")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

func newTestService(t *testing.T, srv *httptest.Server) *firestore.Service {
	t.Helper()
	svc, err := firestore.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
