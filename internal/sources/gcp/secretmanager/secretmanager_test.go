package secretmanager

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

	"google.golang.org/api/option"
	secretmanager "google.golang.org/api/secretmanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call counts to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	secrets  []*secretmanager.Secret
	versions map[string][]*secretmanager.SecretVersion
	listErr  error
	verErr   error
	calls    int
	verCalls int
	project  string
}

func (f *fakeAPI) ListSecrets(_ context.Context, project string) ([]*secretmanager.Secret, error) {
	f.calls++
	f.project = project
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.secrets, nil
}

func (f *fakeAPI) ListSecretVersions(_ context.Context, secretName string) ([]*secretmanager.SecretVersion, error) {
	f.verCalls++
	if f.verErr != nil {
		return nil, f.verErr
	}
	return f.versions[secretName], nil
}

func smReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) secretPayload {
	t.Helper()
	var p secretPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func ptr(n int) *int { return &n }

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.secretmanager" {
		t.Errorf("ID = %q; want gcp.secretmanager", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "secret" {
		t.Errorf("Emits = %v; want [secret]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SortsAndPopulates covers the happy path: a rotated,
// CMEK-encrypted secret with two versions and a never-rotated,
// Google-managed secret with one version emit two records sorted by ID,
// with all required fields and the version-derived rotation signals.
func TestCollect_SortsAndPopulates(t *testing.T) {
	fake := &fakeAPI{
		secrets: []*secretmanager.Secret{
			{ // never rotated, Google-managed encryption, no rotation policy.
				Name:        "projects/p/secrets/api-key",
				Replication: &secretmanager.Replication{Automatic: &secretmanager.Automatic{}},
			},
			{ // rotation policy + automatic CMEK + two versions.
				Name:     "projects/p/secrets/db-pass",
				Rotation: &secretmanager.Rotation{NextRotationTime: "2026-09-01T00:00:00Z"},
				Replication: &secretmanager.Replication{Automatic: &secretmanager.Automatic{
					CustomerManagedEncryption: &secretmanager.CustomerManagedEncryption{
						KmsKeyName: "projects/p/locations/us/keyRings/r/cryptoKeys/k",
					},
				}},
			},
		},
		versions: map[string][]*secretmanager.SecretVersion{
			"projects/p/secrets/api-key": {
				{Name: "projects/p/secrets/api-key/versions/1", CreateTime: "2026-01-01T00:00:00Z"},
			},
			"projects/p/secrets/db-pass": {
				{Name: "projects/p/secrets/db-pass/versions/2", CreateTime: "2026-06-06T00:00:00Z"},
				{Name: "projects/p/secrets/db-pass/versions/1", CreateTime: "2026-03-01T00:00:00Z"},
			},
		},
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), smReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID (full resource name): "...api-key" before "...db-pass".
	if records[0].ID != "projects/p/secrets/api-key" || records[1].ID != "projects/p/secrets/db-pass" {
		t.Fatalf("IDs = %q,%q; want api-key before db-pass", records[0].ID, records[1].ID)
	}
	for i := range records {
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (secrets have no identity)", i, records[i].IdentityKey)
		}
	}

	wantAPIKey := secretPayload{
		ID: "projects/p/secrets/api-key", Name: "api-key", Provider: "gcp",
		RotationEnabled: false, KMSEncrypted: false, NeverRotated: true,
		LastRotatedDays: nil, VersionCount: 1,
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantAPIKey) {
		t.Errorf("api-key payload = %+v; want %+v", got, wantAPIKey)
	}

	wantDBPass := secretPayload{
		ID: "projects/p/secrets/db-pass", Name: "db-pass", Provider: "gcp",
		RotationEnabled: true, KMSEncrypted: true, NeverRotated: false,
		LastRotatedDays: ptr(10), VersionCount: 2, // newest version 2026-06-06 → 10 days before 06-16
	}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantDBPass) {
		t.Errorf("db-pass payload = %+v; want %+v", got, wantDBPass)
	}
}

// TestCmekEnabled covers each replication shape GCP exposes for CMEK.
func TestCmekEnabled(t *testing.T) {
	cme := &secretmanager.CustomerManagedEncryption{KmsKeyName: "projects/p/locations/us/keyRings/r/cryptoKeys/k"}
	cases := map[string]struct {
		secret *secretmanager.Secret
		want   bool
	}{
		"automatic CMEK": {&secretmanager.Secret{Replication: &secretmanager.Replication{
			Automatic: &secretmanager.Automatic{CustomerManagedEncryption: cme}}}, true},
		"user-managed replica CMEK": {&secretmanager.Secret{Replication: &secretmanager.Replication{
			UserManaged: &secretmanager.UserManaged{Replicas: []*secretmanager.Replica{
				{Location: "us-east1"}, {Location: "us-west1", CustomerManagedEncryption: cme}}}}}, true},
		"top-level regionalized CMEK": {&secretmanager.Secret{CustomerManagedEncryption: cme}, true},
		"google-managed automatic":    {&secretmanager.Secret{Replication: &secretmanager.Replication{Automatic: &secretmanager.Automatic{}}}, false},
		"empty key name":              {&secretmanager.Secret{CustomerManagedEncryption: &secretmanager.CustomerManagedEncryption{}}, false},
		"no replication":              {&secretmanager.Secret{}, false},
	}
	for name, c := range cases {
		if got := cmekEnabled(c.secret); got != c.want {
			t.Errorf("%s: cmekEnabled = %v; want %v", name, got, c.want)
		}
	}
}

func TestCollect_NilSecretSkipped(t *testing.T) {
	fake := &fakeAPI{
		secrets: []*secretmanager.Secret{nil, {Name: "projects/p/secrets/real"}},
		versions: map[string][]*secretmanager.SecretVersion{
			"projects/p/secrets/real": {{Name: "projects/p/secrets/real/versions/1", CreateTime: "2026-01-01T00:00:00Z"}},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), smReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil secret skipped)", len(records))
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
	_, err := p.Collect(context.Background(), smReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_PropagatesVersionsError(t *testing.T) {
	wantErr := errors.New("versions boom")
	fake := &fakeAPI{
		secrets: []*secretmanager.Secret{{Name: "projects/p/secrets/x"}},
		verErr:  wantErr,
	}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), smReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{
		secrets: []*secretmanager.Secret{{Name: "projects/p/secrets/x"}},
		versions: map[string][]*secretmanager.SecretVersion{
			"projects/p/secrets/x": {{Name: "projects/p/secrets/x/versions/1", CreateTime: "2026-01-01T00:00:00Z"}},
		},
	}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), smReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

// TestRealSM_ListSecretsAndVersions exercises the production adapter against
// an httptest server, verifying it lists secrets and per-secret versions.
func TestRealSM_ListSecretsAndVersions(t *testing.T) {
	secrets := mustMarshal(t, secretmanager.ListSecretsResponse{
		Secrets: []*secretmanager.Secret{{Name: "projects/p/secrets/x"}},
	})
	versions := mustMarshal(t, secretmanager.ListSecretVersionsResponse{
		Versions: []*secretmanager.SecretVersion{
			{Name: "projects/p/secrets/x/versions/2"},
			{Name: "projects/p/secrets/x/versions/1"},
		},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/versions"):
			_, _ = w.Write(versions) //nolint:errcheck // test handler
		case strings.HasSuffix(r.URL.Path, "/secrets"):
			_, _ = w.Write(secrets) //nolint:errcheck // test handler
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realSM{svc: svc}

	gotSecrets, err := r.ListSecrets(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(gotSecrets) != 1 {
		t.Fatalf("len secrets = %d; want 1", len(gotSecrets))
	}
	gotVersions, err := r.ListSecretVersions(context.Background(), "projects/p/secrets/x")
	if err != nil {
		t.Fatalf("ListSecretVersions: %v", err)
	}
	if len(gotVersions) != 2 {
		t.Fatalf("len versions = %d; want 2", len(gotVersions))
	}
}

// TestRealSM_Error verifies the adapter surfaces HTTP errors.
func TestRealSM_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realSM{svc: svc}
	if _, err := r.ListSecrets(context.Background(), "p"); err == nil {
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

func newTestService(t *testing.T, srv *httptest.Server) *secretmanager.Service {
	t.Helper()
	svc, err := secretmanager.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
