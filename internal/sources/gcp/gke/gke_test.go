package gke

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	container "google.golang.org/api/container/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call count to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	clusters []*container.Cluster
	listErr  error
	calls    int
	project  string
}

func (f *fakeAPI) ListClusters(_ context.Context, project string) ([]*container.Cluster, error) {
	f.calls++
	f.project = project
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.clusters, nil
}

func gkeReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) clusterPayload {
	t.Helper()
	var p clusterPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.gke" {
		t.Errorf("ID = %q; want gcp.gke", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "kubernetes_cluster" {
		t.Errorf("Emits = %v; want [kubernetes_cluster]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SortsAndPopulates covers the happy path: a hardened private
// cluster (secrets encryption ON with CMEK, granular logging, private
// endpoint, all node pools auto-upgrade) and an open cluster (no secrets
// encryption, logging off, public endpoint, a manual-upgrade pool) emit
// two records sorted by ID with every field mapped.
func TestCollect_SortsAndPopulates(t *testing.T) {
	fake := &fakeAPI{
		clusters: []*container.Cluster{
			{ // open cluster, sorts second by SelfLink.
				Name:                 "open",
				SelfLink:             "https://container.googleapis.com/v1/projects/p/zones/us-central1-a/clusters/open",
				Location:             "us-central1-a",
				Status:               "RUNNING",
				CurrentMasterVersion: "1.29.5-gke.100",
				LoggingService:       "none",
				DatabaseEncryption:   &container.DatabaseEncryption{State: "DECRYPTED"},
				NodePools: []*container.NodePool{
					{Name: "default", Management: &container.NodeManagement{AutoUpgrade: true}},
					{Name: "manual", Management: &container.NodeManagement{AutoUpgrade: false}},
				},
			},
			{ // hardened cluster, sorts first by SelfLink.
				Name:                 "hardened",
				SelfLink:             "https://container.googleapis.com/v1/projects/p/locations/us-central1/clusters/hardened",
				Location:             "us-central1",
				Status:               "RUNNING",
				CurrentMasterVersion: "1.30.1-gke.200",
				DatabaseEncryption: &container.DatabaseEncryption{
					State:        "ENCRYPTED",
					CurrentState: "CURRENT_STATE_ENCRYPTED",
					KeyName:      "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k",
				},
				LoggingConfig: &container.LoggingConfig{
					ComponentConfig: &container.LoggingComponentConfig{
						EnableComponents: []string{"SYSTEM_COMPONENTS", "WORKLOADS"},
					},
				},
				PrivateClusterConfig: &container.PrivateClusterConfig{EnablePrivateEndpoint: true},
				ReleaseChannel:       &container.ReleaseChannel{Channel: "REGULAR"},
				NodePools: []*container.NodePool{
					{Name: "a", Management: &container.NodeManagement{AutoUpgrade: true}},
					{Name: "b", Management: &container.NodeManagement{AutoUpgrade: true}},
				},
			},
		},
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), gkeReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID (SelfLink): ".../locations/us-central1/clusters/hardened"
	// sorts before ".../zones/us-central1-a/clusters/open".
	if n0, n1 := decodePayload(t, &records[0]).Name, decodePayload(t, &records[1]).Name; n0 != "hardened" || n1 != "open" {
		t.Fatalf("order = %q,%q; want hardened before open", n0, n1)
	}
	for i := range records {
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (clusters have no identity)", i, records[i].IdentityKey)
		}
	}

	wantHardened := clusterPayload{
		ID:   "https://container.googleapis.com/v1/projects/p/locations/us-central1/clusters/hardened",
		Name: "hardened", Provider: "gcp", Version: "1.30.1-gke.200",
		SecretsEncryptionEnabled: true, LoggingEnabled: true, IsPrivateEndpoint: true, NodeAutoUpgradeEnabled: true,
		Location: "us-central1", Status: "RUNNING",
		KMSKeyName:      "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k",
		EncryptionState: "ENCRYPTED", CurrentState: "CURRENT_STATE_ENCRYPTED", ReleaseChannel: "REGULAR",
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantHardened) {
		t.Errorf("hardened payload = %+v; want %+v", got, wantHardened)
	}

	wantOpen := clusterPayload{
		ID:   "https://container.googleapis.com/v1/projects/p/zones/us-central1-a/clusters/open",
		Name: "open", Provider: "gcp", Version: "1.29.5-gke.100",
		SecretsEncryptionEnabled: false, LoggingEnabled: false, IsPrivateEndpoint: false, NodeAutoUpgradeEnabled: false,
		Location: "us-central1-a", Status: "RUNNING", EncryptionState: "DECRYPTED",
	}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantOpen) {
		t.Errorf("open payload = %+v; want %+v", got, wantOpen)
	}
}

// TestBuildPayload_NilSubStructs verifies a bare cluster (no encryption,
// logging, private, node-pool, or release-channel config) maps to honest
// false values and falls back to Name for the ID when SelfLink is empty.
func TestBuildPayload_NilSubStructs(t *testing.T) {
	got := buildPayload(&container.Cluster{Name: "bare"})
	if got.ID != "bare" {
		t.Errorf("ID = %q; want fallback to name 'bare'", got.ID)
	}
	if got.SecretsEncryptionEnabled || got.LoggingEnabled || got.IsPrivateEndpoint || got.NodeAutoUpgradeEnabled {
		t.Errorf("nil sub-structs should map to false: %+v", got)
	}
	if got.EncryptionState != "" || got.KMSKeyName != "" || got.ReleaseChannel != "" {
		t.Errorf("nil sub-structs should leave extras empty: %+v", got)
	}
}

// TestLoggingEnabled covers the granular-vs-legacy logging precedence.
func TestLoggingEnabled(t *testing.T) {
	cases := map[string]struct {
		cluster *container.Cluster
		want    bool
	}{
		"granular components on": {&container.Cluster{LoggingConfig: &container.LoggingConfig{
			ComponentConfig: &container.LoggingComponentConfig{EnableComponents: []string{"SYSTEM_COMPONENTS"}}}}, true},
		"granular empty, legacy on": {&container.Cluster{
			LoggingConfig:  &container.LoggingConfig{ComponentConfig: &container.LoggingComponentConfig{}},
			LoggingService: "logging.googleapis.com/kubernetes"}, true},
		"granular empty, legacy none": {&container.Cluster{
			LoggingConfig:  &container.LoggingConfig{ComponentConfig: &container.LoggingComponentConfig{}},
			LoggingService: "none"}, false},
		"legacy on, no config":   {&container.Cluster{LoggingService: "logging.googleapis.com/kubernetes"}, true},
		"legacy none, no config": {&container.Cluster{LoggingService: "none"}, false},
		"nothing set":            {&container.Cluster{}, false},
	}
	for name, c := range cases {
		if got := loggingEnabled(c.cluster); got != c.want {
			t.Errorf("%s: loggingEnabled = %v; want %v", name, got, c.want)
		}
	}
}

// TestNodeAutoUpgradeEnabled covers the all-pools-must-be-on aggregation.
func TestNodeAutoUpgradeEnabled(t *testing.T) {
	cases := map[string]struct {
		pools []*container.NodePool
		want  bool
	}{
		"no pools": {nil, false},
		"all on": {[]*container.NodePool{
			{Management: &container.NodeManagement{AutoUpgrade: true}},
			{Management: &container.NodeManagement{AutoUpgrade: true}}}, true},
		"one off": {[]*container.NodePool{
			{Management: &container.NodeManagement{AutoUpgrade: true}},
			{Management: &container.NodeManagement{AutoUpgrade: false}}}, false},
		"nil management": {[]*container.NodePool{{}}, false},
		"nil pool":       {[]*container.NodePool{nil}, false},
	}
	for name, c := range cases {
		if got := nodeAutoUpgradeEnabled(&container.Cluster{NodePools: c.pools}); got != c.want {
			t.Errorf("%s: nodeAutoUpgradeEnabled = %v; want %v", name, got, c.want)
		}
	}
}

func TestCollect_NilClusterSkipped(t *testing.T) {
	fake := &fakeAPI{clusters: []*container.Cluster{nil, {Name: "real", SelfLink: "self/real"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), gkeReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil cluster skipped)", len(records))
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
	_, err := p.Collect(context.Background(), gkeReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{clusters: []*container.Cluster{{Name: "c", SelfLink: "self/c"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), gkeReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

// TestRealGKE_ListClusters exercises the production adapter against an
// httptest server, verifying it lists clusters via the all-locations
// wildcard in one call.
func TestRealGKE_ListClusters(t *testing.T) {
	body := mustMarshal(t, container.ListClustersResponse{
		Clusters: []*container.Cluster{
			{Name: "regional", SelfLink: "self/regional"},
			{Name: "zonal", SelfLink: "self/zonal"},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realGKE{svc: newTestService(t, srv)}
	clusters, err := r.ListClusters(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if len(clusters) != 2 {
		t.Fatalf("len = %d; want 2", len(clusters))
	}
}

// TestRealGKE_Error verifies the adapter surfaces HTTP errors.
func TestRealGKE_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	r := &realGKE{svc: newTestService(t, srv)}
	if _, err := r.ListClusters(context.Background(), "p"); err == nil {
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

func newTestService(t *testing.T, srv *httptest.Server) *container.Service {
	t.Helper()
	svc, err := container.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
