package network

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	gce "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without hitting GCP. It records call counts to
// assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	networks []*gce.Network
	subnets  []*gce.Subnetwork
	err      error
	subErr   error
	netCalls int
	subCalls int
	project  string
}

func (f *fakeAPI) ListNetworks(_ context.Context, project string) ([]*gce.Network, error) {
	f.netCalls++
	f.project = project
	if f.err != nil {
		return nil, f.err
	}
	return f.networks, nil
}

func (f *fakeAPI) AggregatedListSubnetworks(_ context.Context, _ string) ([]*gce.Subnetwork, error) {
	f.subCalls++
	if f.subErr != nil {
		return nil, f.subErr
	}
	return f.subnets, nil
}

func netReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) networkPayload {
	t.Helper()
	var p networkPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

// subnet builds a custom-mode subnetwork on the given network with flow
// logs set via the modern LogConfig.Enable flag.
func subnet(network string, logsOn bool) *gce.Subnetwork {
	return &gce.Subnetwork{
		Network:   "projects/p/global/networks/" + network,
		LogConfig: &gce.SubnetworkLogConfig{Enable: logsOn},
	}
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.network" {
		t.Errorf("ID = %q; want gcp.network", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "network" {
		t.Errorf("Emits = %v; want [network]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SortsAndPopulates covers the happy path: two networks emit
// two records sorted by ID, each with the required fields and GCP extras.
// The default network is flagged; a custom network with one logged and
// one unlogged subnet reports flow_logs_enabled=false (ALL-must-be-on).
func TestCollect_SortsAndPopulates(t *testing.T) {
	fake := &fakeAPI{
		networks: []*gce.Network{
			{ // custom-mode "prod" VPC, regional routing, one subnet logged one not.
				Name:          "prod",
				RoutingConfig: &gce.NetworkRoutingConfig{RoutingMode: "REGIONAL"},
			},
			{ // auto-mode default VPC, all subnets logged.
				Name:                  "default",
				AutoCreateSubnetworks: true,
				RoutingConfig:         &gce.NetworkRoutingConfig{RoutingMode: "GLOBAL"},
			},
		},
		subnets: []*gce.Subnetwork{
			subnet("prod", true),
			subnet("prod", false),
			subnet("default", true),
		},
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), netReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID: "default" before "prod".
	if records[0].ID != "default" || records[1].ID != "prod" {
		t.Fatalf("IDs = %q,%q; want default,prod", records[0].ID, records[1].ID)
	}
	for i := range records {
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (networks have no identity)", i, records[i].IdentityKey)
		}
	}

	wantDefault := networkPayload{
		ID: "default", Name: "default", Provider: "gcp",
		FlowLogsEnabled: true, IsDefault: true,
		AutoCreateSubnetworks: true, RoutingMode: "GLOBAL", IsLegacy: false, SubnetCount: 1,
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantDefault) {
		t.Errorf("default payload = %+v; want %+v", got, wantDefault)
	}

	wantProd := networkPayload{
		ID: "prod", Name: "prod", Provider: "gcp",
		FlowLogsEnabled: false, IsDefault: false,
		AutoCreateSubnetworks: false, RoutingMode: "REGIONAL", IsLegacy: false, SubnetCount: 2,
	}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantProd) {
		t.Errorf("prod payload = %+v; want %+v", got, wantProd)
	}
}

// TestCollect_NoSubnetsNotLogged verifies a network with zero subnetworks
// reports flow_logs_enabled=false (not vacuously compliant).
func TestCollect_NoSubnetsNotLogged(t *testing.T) {
	fake := &fakeAPI{networks: []*gce.Network{{Name: "empty"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), netReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1", len(records))
	}
	got := decodePayload(t, &records[0])
	if got.FlowLogsEnabled || got.SubnetCount != 0 {
		t.Errorf("got flow_logs=%v subnets=%d; want false, 0", got.FlowLogsEnabled, got.SubnetCount)
	}
}

// TestCollect_LegacyFlagAndFallback verifies a legacy network (IPv4Range
// set) is flagged is_legacy with cidr_block populated, and that the legacy
// EnableFlowLogs bool is honored when LogConfig is absent.
func TestCollect_LegacyFlagAndFallback(t *testing.T) {
	fake := &fakeAPI{
		networks: []*gce.Network{{Name: "legacy", IPv4Range: "10.240.0.0/16"}},
		subnets: []*gce.Subnetwork{
			// LogConfig nil → falls back to the legacy EnableFlowLogs bool.
			{Network: "projects/p/global/networks/legacy", EnableFlowLogs: true},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), netReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := decodePayload(t, &records[0])
	if !got.IsLegacy || got.CIDRBlock != "10.240.0.0/16" {
		t.Errorf("got is_legacy=%v cidr=%q; want true, 10.240.0.0/16", got.IsLegacy, got.CIDRBlock)
	}
	if !got.FlowLogsEnabled {
		t.Errorf("got flow_logs=%v; want true (legacy EnableFlowLogs fallback)", got.FlowLogsEnabled)
	}
}

func TestCollect_NilNetworkSkipped(t *testing.T) {
	fake := &fakeAPI{networks: []*gce.Network{nil, {Name: "real"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), netReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil network skipped)", len(records))
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"firewall_rule"}})
	if err == nil {
		t.Fatal("want error for unaccepted type; got nil")
	}
}

func TestCollect_PropagatesNetworkError(t *testing.T) {
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{err: wantErr}})
	_, err := p.Collect(context.Background(), netReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_PropagatesSubnetError(t *testing.T) {
	wantErr := errors.New("subnet boom")
	p := New(Options{API: &fakeAPI{networks: []*gce.Network{{Name: "n"}}, subErr: wantErr}})
	_, err := p.Collect(context.Background(), netReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{networks: []*gce.Network{{Name: "n"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), netReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.netCalls != 3 || fake.subCalls != 3 {
		t.Errorf("calls = net %d / sub %d; want 3/3 (no caching per KISS-no-DRY)", fake.netCalls, fake.subCalls)
	}
}

func TestShortName(t *testing.T) {
	cases := map[string]string{
		"projects/p/global/networks/default": "default",
		"default":                            "default",
		"":                                   "",
	}
	for in, want := range cases {
		if got := shortName(in); got != want {
			t.Errorf("shortName(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestRealNetwork_ListNetworks_Pagination exercises the production adapter
// against an httptest server, verifying it pages through NextPageToken.
func TestRealNetwork_ListNetworks_Pagination(t *testing.T) {
	page1 := mustMarshal(t, gce.NetworkList{Items: []*gce.Network{{Name: "net-a"}}, NextPageToken: "page2"})
	page2 := mustMarshal(t, gce.NetworkList{Items: []*gce.Network{{Name: "net-b"}}})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("pageToken") {
		case "":
			_, _ = w.Write(page1) //nolint:errcheck // test handler
		case "page2":
			_, _ = w.Write(page2) //nolint:errcheck // test handler
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realNetwork{svc: svc}
	networks, err := r.ListNetworks(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(networks) != 2 || networks[0].Name != "net-a" || networks[1].Name != "net-b" {
		t.Fatalf("networks = %+v; want net-a,net-b across pages", networks)
	}
}

// TestRealNetwork_AggregatedListSubnetworks flattens the scoped-list map
// across regions into a single slice.
func TestRealNetwork_AggregatedListSubnetworks(t *testing.T) {
	body := mustMarshal(t, gce.SubnetworkAggregatedList{
		Items: map[string]gce.SubnetworksScopedList{
			"regions/us-central1":  {Subnetworks: []*gce.Subnetwork{{Name: "sub-a"}}},
			"regions/europe-west1": {Subnetworks: []*gce.Subnetwork{{Name: "sub-b"}}},
		},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realNetwork{svc: svc}
	subnets, err := r.AggregatedListSubnetworks(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("AggregatedListSubnetworks: %v", err)
	}
	if len(subnets) != 2 {
		t.Fatalf("len = %d; want 2 (flattened across regions)", len(subnets))
	}
}

// TestRealNetwork_Error verifies the adapter surfaces HTTP errors.
func TestRealNetwork_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	svc := newTestService(t, srv)
	r := &realNetwork{svc: svc}
	if _, err := r.ListNetworks(context.Background(), "proj-1"); err == nil {
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

func newTestService(t *testing.T, srv *httptest.Server) *gce.Service {
	t.Helper()
	svc, err := gce.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
