package artifactregistry

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

	artifactregistry "google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call counts to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	repos     []*artifactregistry.Repository
	policies  map[string]*artifactregistry.Policy
	listErr   error
	policyErr error
	calls     int
	iamCalls  int
	project   string
}

func (f *fakeAPI) ListRepositories(_ context.Context, project string) ([]*artifactregistry.Repository, error) {
	f.calls++
	f.project = project
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.repos, nil
}

func (f *fakeAPI) GetIamPolicy(_ context.Context, repoName string) (*artifactregistry.Policy, error) {
	f.iamCalls++
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return f.policies[repoName], nil
}

func arReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) registryPayload {
	t.Helper()
	var p registryPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.artifactregistry" {
		t.Errorf("ID = %q; want gcp.artifactregistry", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "container_registry" {
		t.Errorf("Emits = %v; want [container_registry]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SortsAndPopulates covers the happy path: a hardened private
// Docker repo (scanning active, immutable tags, CMEK, no public access) and
// a public repo (scanning disabled, mutable, Google-managed, allUsers) emit
// two records sorted by ID with every field mapped.
func TestCollect_SortsAndPopulates(t *testing.T) {
	fake := &fakeAPI{
		repos: []*artifactregistry.Repository{
			{ // public, scanning off, Google-managed, mutable.
				Name:                        "projects/p/locations/us/repositories/public-images",
				Format:                      "DOCKER",
				Mode:                        "STANDARD_REPOSITORY",
				RegistryUri:                 "us-docker.pkg.dev/p/public-images",
				VulnerabilityScanningConfig: &artifactregistry.VulnerabilityScanningConfig{EnablementState: "SCANNING_DISABLED"},
			},
			{ // hardened: scanning active, CMEK, immutable tags, private.
				Name:                        "projects/p/locations/us/repositories/app",
				Format:                      "DOCKER",
				Mode:                        "STANDARD_REPOSITORY",
				RegistryUri:                 "us-docker.pkg.dev/p/app",
				KmsKeyName:                  "projects/p/locations/us/keyRings/r/cryptoKeys/k",
				DockerConfig:                &artifactregistry.DockerRepositoryConfig{ImmutableTags: true},
				VulnerabilityScanningConfig: &artifactregistry.VulnerabilityScanningConfig{EnablementState: "SCANNING_ACTIVE"},
			},
		},
		policies: map[string]*artifactregistry.Policy{
			"projects/p/locations/us/repositories/public-images": {Bindings: []*artifactregistry.Binding{
				{Role: "roles/artifactregistry.reader", Members: []string{"allUsers"}},
			}},
			"projects/p/locations/us/repositories/app": {Bindings: []*artifactregistry.Binding{
				{Role: "roles/artifactregistry.reader", Members: []string{"user:dev@example.com"}},
			}},
		},
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), arReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID (full resource name): "...app" before "...public-images".
	if records[0].ID != "projects/p/locations/us/repositories/app" ||
		records[1].ID != "projects/p/locations/us/repositories/public-images" {
		t.Fatalf("IDs = %q,%q; want app before public-images", records[0].ID, records[1].ID)
	}
	for i := range records {
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (registries have no identity)", i, records[i].IdentityKey)
		}
	}

	wantApp := registryPayload{
		ID: "projects/p/locations/us/repositories/app", Name: "app", Provider: "gcp",
		ScanOnPushEnabled: true, ImageImmutabilityEnabled: true, IsPublic: false, EncryptionEnabled: true,
		Format: "DOCKER", Mode: "STANDARD_REPOSITORY", IsCustomerManaged: true,
		KMSKeyName: "projects/p/locations/us/keyRings/r/cryptoKeys/k", ScanningState: "SCANNING_ACTIVE",
		RegistryURI: "us-docker.pkg.dev/p/app",
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantApp) {
		t.Errorf("app payload = %+v; want %+v", got, wantApp)
	}

	wantPublic := registryPayload{
		ID: "projects/p/locations/us/repositories/public-images", Name: "public-images", Provider: "gcp",
		ScanOnPushEnabled: false, ImageImmutabilityEnabled: false, IsPublic: true, EncryptionEnabled: true,
		Format: "DOCKER", Mode: "STANDARD_REPOSITORY", IsCustomerManaged: false,
		ScanningState: "SCANNING_DISABLED", RegistryURI: "us-docker.pkg.dev/p/public-images",
	}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantPublic) {
		t.Errorf("public-images payload = %+v; want %+v", got, wantPublic)
	}
}

// TestBuildPayload_NilSubStructs verifies a repository with no scanning
// config and no docker config maps to honest false values (not a panic).
func TestBuildPayload_NilSubStructs(t *testing.T) {
	repo := &artifactregistry.Repository{Name: "projects/p/locations/us/repositories/generic", Format: "GENERIC"}
	got := buildPayload(repo, nil)
	if got.ScanOnPushEnabled || got.ImageImmutabilityEnabled || got.IsPublic || got.IsCustomerManaged {
		t.Errorf("nil sub-structs should map to false: %+v", got)
	}
	if !got.EncryptionEnabled {
		t.Error("encryption_enabled should always be true for Artifact Registry")
	}
	if got.ScanningState != "" {
		t.Errorf("scanning_state = %q; want empty for nil config", got.ScanningState)
	}
}

// TestIsPublic covers the IAM public-member detection across binding shapes.
func TestIsPublic(t *testing.T) {
	cases := map[string]struct {
		policy *artifactregistry.Policy
		want   bool
	}{
		"nil policy":            {nil, false},
		"no bindings":           {&artifactregistry.Policy{}, false},
		"allUsers":              {&artifactregistry.Policy{Bindings: []*artifactregistry.Binding{{Members: []string{"allUsers"}}}}, true},
		"allAuthenticatedUsers": {&artifactregistry.Policy{Bindings: []*artifactregistry.Binding{{Members: []string{"allAuthenticatedUsers"}}}}, true},
		"only named members":    {&artifactregistry.Policy{Bindings: []*artifactregistry.Binding{{Members: []string{"user:a@b.com", "group:g@b.com"}}}}, false},
		"nil binding skipped":   {&artifactregistry.Policy{Bindings: []*artifactregistry.Binding{nil, {Members: []string{"allUsers"}}}}, true},
		"public in 2nd binding": {&artifactregistry.Policy{Bindings: []*artifactregistry.Binding{{Members: []string{"user:a@b.com"}}, {Members: []string{"allAuthenticatedUsers"}}}}, true},
	}
	for name, c := range cases {
		if got := isPublic(c.policy); got != c.want {
			t.Errorf("%s: isPublic = %v; want %v", name, got, c.want)
		}
	}
}

func TestCollect_NilRepoSkipped(t *testing.T) {
	fake := &fakeAPI{
		repos: []*artifactregistry.Repository{nil, {Name: "projects/p/locations/us/repositories/real"}},
		policies: map[string]*artifactregistry.Policy{
			"projects/p/locations/us/repositories/real": {},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), arReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil repo skipped)", len(records))
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
	_, err := p.Collect(context.Background(), arReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_PropagatesIamPolicyError(t *testing.T) {
	wantErr := errors.New("iam boom")
	fake := &fakeAPI{
		repos:     []*artifactregistry.Repository{{Name: "projects/p/locations/us/repositories/x"}},
		policyErr: wantErr,
	}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), arReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{
		repos: []*artifactregistry.Repository{{Name: "projects/p/locations/us/repositories/x"}},
		policies: map[string]*artifactregistry.Policy{
			"projects/p/locations/us/repositories/x": {},
		},
	}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), arReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
	if fake.iamCalls != 3 {
		t.Errorf("iamCalls = %d; want 3", fake.iamCalls)
	}
}

// TestRealAR_ListRepositories exercises the production adapter against an
// httptest server, verifying it walks locations and lists repositories per
// location, flattening the result.
func TestRealAR_ListRepositories(t *testing.T) {
	locations := mustMarshal(t, artifactregistry.ListLocationsResponse{
		Locations: []*artifactregistry.Location{
			{LocationId: "us"}, {LocationId: "europe"},
		},
	})
	reposUS := mustMarshal(t, artifactregistry.ListRepositoriesResponse{
		Repositories: []*artifactregistry.Repository{{Name: "projects/p/locations/us/repositories/a"}},
	})
	reposEU := mustMarshal(t, artifactregistry.ListRepositoriesResponse{
		Repositories: []*artifactregistry.Repository{{Name: "projects/p/locations/europe/repositories/b"}},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/locations"):
			_, _ = w.Write(locations) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/locations/us/repositories"):
			_, _ = w.Write(reposUS) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/locations/europe/repositories"):
			_, _ = w.Write(reposEU) //nolint:errcheck // test handler
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realAR{svc: svc}

	repos, err := r.ListRepositories(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("len = %d; want 2 (one per location)", len(repos))
	}
}

// TestRealAR_GetIamPolicy exercises the per-repository IAM policy read.
func TestRealAR_GetIamPolicy(t *testing.T) {
	policy := mustMarshal(t, artifactregistry.Policy{
		Bindings: []*artifactregistry.Binding{{Role: "roles/viewer", Members: []string{"allUsers"}}},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(policy) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realAR{svc: svc}
	got, err := r.GetIamPolicy(context.Background(), "projects/p/locations/us/repositories/a")
	if err != nil {
		t.Fatalf("GetIamPolicy: %v", err)
	}
	if !isPublic(got) {
		t.Error("expected public policy from allUsers binding")
	}
}

// TestRealAR_Error verifies the adapter surfaces HTTP errors.
func TestRealAR_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realAR{svc: svc}
	if _, err := r.ListRepositories(context.Background(), "p"); err == nil {
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

func newTestService(t *testing.T, srv *httptest.Server) *artifactregistry.Service {
	t.Helper()
	svc, err := artifactregistry.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
