package firewall

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

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call count to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	firewalls []*gce.Firewall
	err       error
	calls     int
	project   string
}

func (f *fakeAPI) ListFirewalls(_ context.Context, project string) ([]*gce.Firewall, error) {
	f.calls++
	f.project = project
	if f.err != nil {
		return nil, f.err
	}
	return f.firewalls, nil
}

func fwReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

// assertRecordMeta checks the record-level (non-payload) fields for each
// flattened firewall rule: ID ordering, Type/SourceID, CollectedAt, and
// that IdentityKey stays empty (firewall rules have no cross-source
// identity, unlike directory_user).
func assertRecordMeta(t *testing.T, records []core.EvidenceRecord, wantIDs []string, now time.Time) {
	t.Helper()
	for i, want := range wantIDs {
		if records[i].ID != want {
			t.Errorf("records[%d].ID = %q; want %q", i, records[i].ID, want)
		}
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (firewall rules have no identity)", i, records[i].IdentityKey)
		}
	}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) rulePayload {
	t.Helper()
	var p rulePayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.firewall" {
		t.Errorf("ID = %q; want gcp.firewall", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "firewall_rule" {
		t.Errorf("Emits = %v; want [firewall_rule]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_FlattensAndSorts checks the core flattening: a firewall
// with two allowed protocol entries (one multi-port) expands into one
// record per (protocol, port-range), each carrying the cross-vendor
// fields, and records are sorted by ID.
func TestCollect_FlattensAndSorts(t *testing.T) {
	fake := &fakeAPI{firewalls: []*gce.Firewall{
		{ // allow-web: open to the internet on tcp 80 and 443.
			Name:         "allow-web",
			Direction:    "INGRESS",
			Network:      "projects/p/global/networks/default",
			Priority:     1000,
			SourceRanges: []string{"0.0.0.0/0"},
			Allowed: []*gce.FirewallAllowed{
				{IPProtocol: "tcp", Ports: []string{"80", "443"}},
				{IPProtocol: "icmp"},
			},
		},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), fwReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	// tcp:80, tcp:443, icmp:all → 3 flattened records.
	if len(records) != 3 {
		t.Fatalf("len = %d; want 3", len(records))
	}
	// IDs sorted ascending: ":0", ":1", ":2".
	wantIDs := []string{"allow-web:ingress:0", "allow-web:ingress:1", "allow-web:ingress:2"}
	assertRecordMeta(t, records, wantIDs, now)

	want0 := rulePayload{
		ID: "allow-web:ingress:0", Name: "allow-web ingress rule", Provider: "gcp",
		GroupID: "allow-web", Direction: "ingress", Protocol: "tcp",
		FromPort: 80, ToPort: 80, IsUnrestrictedIPv4: true, IsUnrestrictedIPv6: false,
		SourceCIDR: "0.0.0.0/0", Action: "allow", Network: "default", Priority: 1000, Disabled: false,
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, want0) {
		t.Errorf("records[0] payload = %+v; want %+v", got, want0)
	}
	// Second port of the tcp entry.
	if got := decodePayload(t, &records[1]); got.FromPort != 443 || got.ToPort != 443 || got.Protocol != "tcp" {
		t.Errorf("records[1] = %+v; want tcp 443/443", got)
	}
	// icmp entry has no ports → all-ports sentinel.
	got2 := decodePayload(t, &records[2])
	if got2.Protocol != "icmp" || got2.FromPort != allPortsSentinel || got2.ToPort != allPortsSentinel {
		t.Errorf("records[2] = %+v; want icmp -1/-1", got2)
	}
}

// TestCollect_PortRange verifies a "80-443" range maps to from/to.
func TestCollect_PortRange(t *testing.T) {
	fake := &fakeAPI{firewalls: []*gce.Firewall{{
		Name: "fw", Direction: "INGRESS", SourceRanges: []string{"10.0.0.0/8"},
		Allowed: []*gce.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"80-443"}}},
	}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), fwReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1", len(records))
	}
	got := decodePayload(t, &records[0])
	if got.FromPort != 80 || got.ToPort != 443 {
		t.Errorf("port range = %d-%d; want 80-443", got.FromPort, got.ToPort)
	}
	if got.IsUnrestrictedIPv4 || got.SourceCIDR != "10.0.0.0/8" {
		t.Errorf("got unrestricted=%v cidr=%q; want false, 10.0.0.0/8", got.IsUnrestrictedIPv4, got.SourceCIDR)
	}
}

// TestCollect_EgressDeny verifies egress direction reads DestinationRanges,
// detects open IPv6, and maps a Denied entry to action=deny.
func TestCollect_EgressDeny(t *testing.T) {
	fake := &fakeAPI{firewalls: []*gce.Firewall{{
		Name: "deny-all-egress", Direction: "EGRESS", DestinationRanges: []string{"::/0"},
		Denied: []*gce.FirewallDenied{{IPProtocol: "all"}},
	}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), fwReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1", len(records))
	}
	got := decodePayload(t, &records[0])
	if got.Direction != "egress" || got.Action != "deny" || got.Protocol != "all" {
		t.Errorf("got dir=%q action=%q proto=%q; want egress/deny/all", got.Direction, got.Action, got.Protocol)
	}
	if !got.IsUnrestrictedIPv6 || got.IsUnrestrictedIPv4 {
		t.Errorf("got v6=%v v4=%v; want true, false", got.IsUnrestrictedIPv6, got.IsUnrestrictedIPv4)
	}
	if got.DestCIDR != "::/0" || got.SourceCIDR != "" {
		t.Errorf("got dest=%q source=%q; want ::/0, empty", got.DestCIDR, got.SourceCIDR)
	}
	if got.FromPort != allPortsSentinel || got.ToPort != allPortsSentinel {
		t.Errorf("got ports %d/%d; want -1/-1 (all)", got.FromPort, got.ToPort)
	}
}

func TestCollect_NilFirewallSkipped(t *testing.T) {
	fake := &fakeAPI{firewalls: []*gce.Firewall{
		nil,
		{Name: "fw", Direction: "INGRESS", Allowed: []*gce.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), fwReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil firewall skipped)", len(records))
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil {
		t.Fatal("want error for unaccepted type; got nil")
	}
}

func TestCollect_PropagatesAPIError(t *testing.T) {
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{err: wantErr}})
	_, err := p.Collect(context.Background(), fwReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{firewalls: []*gce.Firewall{
		{Name: "fw", Direction: "INGRESS", Allowed: []*gce.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}},
	}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), fwReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

func TestParsePortRange(t *testing.T) {
	cases := []struct {
		in       string
		from, to int
	}{
		{"22", 22, 22},
		{"80-443", 80, 443},
		{"", allPortsSentinel, allPortsSentinel},
		{"bogus", allPortsSentinel, allPortsSentinel},
		{"1-bad", allPortsSentinel, allPortsSentinel},
	}
	for _, c := range cases {
		from, to := parsePortRange(c.in)
		if from != c.from || to != c.to {
			t.Errorf("parsePortRange(%q) = %d,%d; want %d,%d", c.in, from, to, c.from, c.to)
		}
	}
}

// TestRealFirewall_ListFirewalls_Pagination exercises the production
// adapter against an httptest server, verifying it pages through
// NextPageToken and accumulates firewalls across pages.
func TestRealFirewall_ListFirewalls_Pagination(t *testing.T) {
	page1, err := json.Marshal(gce.FirewallList{
		Items:         []*gce.Firewall{{Name: "fw-a"}},
		NextPageToken: "page2",
	})
	if err != nil {
		t.Fatalf("marshal page1: %v", err)
	}
	page2, err := json.Marshal(gce.FirewallList{
		Items: []*gce.Firewall{{Name: "fw-b"}},
	})
	if err != nil {
		t.Fatalf("marshal page2: %v", err)
	}

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

	svc, err := gce.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	r := &realFirewall{svc: svc}
	firewalls, err := r.ListFirewalls(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("ListFirewalls: %v", err)
	}
	if len(firewalls) != 2 {
		t.Fatalf("len = %d; want 2 (both pages)", len(firewalls))
	}
	if firewalls[0].Name != "fw-a" || firewalls[1].Name != "fw-b" {
		t.Errorf("names = %q,%q; want fw-a,fw-b", firewalls[0].Name, firewalls[1].Name)
	}
}

// TestRealFirewall_ListFirewalls_Error verifies the adapter surfaces HTTP
// errors from the Compute API.
func TestRealFirewall_ListFirewalls_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	svc, err := gce.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	r := &realFirewall{svc: svc}
	if _, err := r.ListFirewalls(context.Background(), "proj-1"); err == nil {
		t.Fatal("want error from 403; got nil")
	}
}
