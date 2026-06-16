package kms

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call count to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	keys    []*cloudkms.CryptoKey
	err     error
	calls   int
	project string
}

func (f *fakeAPI) ListCryptoKeys(_ context.Context, project string) ([]*cloudkms.CryptoKey, error) {
	f.calls++
	f.project = project
	if f.err != nil {
		return nil, f.err
	}
	return f.keys, nil
}

func kmsReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) keyPayload {
	t.Helper()
	var p keyPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.kms" {
		t.Errorf("ID = %q; want gcp.kms", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "kms_key" {
		t.Errorf("Emits = %v; want [kms_key]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SortsAndPopulates covers the happy path: a rotated
// symmetric key and a non-rotated asymmetric key emit two records sorted
// by ID (the full resource name), with all required fields and GCP extras.
func TestCollect_SortsAndPopulates(t *testing.T) {
	fake := &fakeAPI{keys: []*cloudkms.CryptoKey{
		{ // symmetric, rotated every 90 days, enabled primary.
			Name:            "projects/p/locations/us/keyRings/r/cryptoKeys/sym",
			Purpose:         "ENCRYPT_DECRYPT",
			RotationPeriod:  "7776000s",
			Primary:         &cloudkms.CryptoKeyVersion{State: "ENABLED"},
			VersionTemplate: &cloudkms.CryptoKeyVersionTemplate{ProtectionLevel: "HSM"},
		},
		{ // asymmetric signing key: no rotation, no primary.
			Name:            "projects/p/locations/global/keyRings/r/cryptoKeys/asym",
			Purpose:         "ASYMMETRIC_SIGN",
			VersionTemplate: &cloudkms.CryptoKeyVersionTemplate{ProtectionLevel: "SOFTWARE"},
		},
	}}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), kmsReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID (full resource name): "...asym" before "...sym".
	if !strings.HasSuffix(records[0].ID, "/asym") || !strings.HasSuffix(records[1].ID, "/sym") {
		t.Fatalf("IDs = %q,%q; want asym before sym", records[0].ID, records[1].ID)
	}
	for i := range records {
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (kms keys have no identity)", i, records[i].IdentityKey)
		}
	}

	wantSym := keyPayload{
		KeyID:      "projects/p/locations/us/keyRings/r/cryptoKeys/sym",
		KeyManager: "CUSTOMER", IsCustomerManaged: true, Enabled: true, RotationEnabled: true,
		Provider: "gcp", Purpose: "ENCRYPT_DECRYPT", ProtectionLevel: "HSM",
		RotationPeriodDays: 90, PrimaryState: "ENABLED",
	}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantSym) {
		t.Errorf("sym payload = %+v; want %+v", got, wantSym)
	}

	wantAsym := keyPayload{
		KeyID:      "projects/p/locations/global/keyRings/r/cryptoKeys/asym",
		KeyManager: "CUSTOMER", IsCustomerManaged: true, Enabled: true, RotationEnabled: false,
		Provider: "gcp", Purpose: "ASYMMETRIC_SIGN", ProtectionLevel: "SOFTWARE",
		RotationPeriodDays: 0, PrimaryState: "",
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantAsym) {
		t.Errorf("asym payload = %+v; want %+v", got, wantAsym)
	}
}

// TestCollect_DisabledPrimary verifies a symmetric key whose primary
// version is disabled reports enabled=false.
func TestCollect_DisabledPrimary(t *testing.T) {
	fake := &fakeAPI{keys: []*cloudkms.CryptoKey{{
		Name:    "projects/p/locations/us/keyRings/r/cryptoKeys/k",
		Purpose: "ENCRYPT_DECRYPT",
		Primary: &cloudkms.CryptoKeyVersion{State: "DISABLED"},
	}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), kmsReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := decodePayload(t, &records[0])
	if got.Enabled || got.PrimaryState != "DISABLED" {
		t.Errorf("got enabled=%v primary_state=%q; want false, DISABLED", got.Enabled, got.PrimaryState)
	}
}

func TestCollect_NilKeySkipped(t *testing.T) {
	fake := &fakeAPI{keys: []*cloudkms.CryptoKey{nil, {Name: "projects/p/locations/us/keyRings/r/cryptoKeys/real"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), kmsReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil key skipped)", len(records))
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"secret"}})
	if err == nil {
		t.Fatal("want error for unaccepted type; got nil")
	}
}

func TestCollect_PropagatesAPIError(t *testing.T) {
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{err: wantErr}})
	_, err := p.Collect(context.Background(), kmsReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{keys: []*cloudkms.CryptoKey{{Name: "projects/p/locations/us/keyRings/r/cryptoKeys/k"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), kmsReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

func TestRotationPeriodDays(t *testing.T) {
	cases := map[string]int{
		"7776000s": 90,
		"86400s":   1,
		"":         0,
		"bogus":    0,
		"100":      0, // missing trailing 's' → Atoi("100")=100, /86400 = 0
	}
	for in, want := range cases {
		if got := rotationPeriodDays(in); got != want {
			t.Errorf("rotationPeriodDays(%q) = %d; want %d", in, got, want)
		}
	}
}

// TestRealKMS_ListCryptoKeys exercises the production adapter against an
// httptest server, verifying it walks locations → keyRings → cryptoKeys
// and flattens keys across locations.
func TestRealKMS_ListCryptoKeys(t *testing.T) {
	locations := mustMarshal(t, cloudkms.ListLocationsResponse{
		Locations: []*cloudkms.Location{{LocationId: "us"}, {LocationId: "global"}},
	})
	keyRings := mustMarshal(t, cloudkms.ListKeyRingsResponse{
		KeyRings: []*cloudkms.KeyRing{{Name: "projects/p/locations/x/keyRings/r"}},
	})
	cryptoKeys := func(name string) []byte {
		return mustMarshal(t, cloudkms.ListCryptoKeysResponse{
			CryptoKeys: []*cloudkms.CryptoKey{{Name: name}},
		})
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/cryptoKeys"):
			// Distinguish the two locations by their keyRings parent path.
			if strings.Contains(path, "/locations/us/") {
				_, _ = w.Write(cryptoKeys("projects/p/locations/us/keyRings/r/cryptoKeys/k-us")) //nolint:errcheck // test handler
			} else {
				_, _ = w.Write(cryptoKeys("projects/p/locations/global/keyRings/r/cryptoKeys/k-global")) //nolint:errcheck // test handler
			}
		case strings.HasSuffix(path, "/keyRings"):
			_, _ = w.Write(keyRings) //nolint:errcheck // test handler
		case strings.HasSuffix(path, "/locations"):
			_, _ = w.Write(locations) //nolint:errcheck // test handler
		default:
			http.Error(w, "unexpected path "+path, http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realKMS{svc: svc}
	keys, err := r.ListCryptoKeys(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListCryptoKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("len = %d; want 2 (one key per location, flattened)", len(keys))
	}
}

// TestRealKMS_Error verifies the adapter surfaces HTTP errors from the
// first-level locations list.
func TestRealKMS_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realKMS{svc: svc}
	if _, err := r.ListCryptoKeys(context.Background(), "p"); err == nil {
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

func newTestService(t *testing.T, srv *httptest.Server) *cloudkms.Service {
	t.Helper()
	svc, err := cloudkms.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
