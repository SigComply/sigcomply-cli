package compute

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	gce "google.golang.org/api/compute/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// Shared fixture literals, named so goconst stays quiet.
const (
	testStatusRunning = "RUNNING"
	testBastion       = "bastion"
)

// fakeAPI lets tests drive the plugin without real GCE calls.
type fakeAPI struct {
	instances []*gce.Instance
	err       error

	listCount int
}

func (f *fakeAPI) AggregatedListInstances(_ context.Context, _ string) ([]*gce.Instance, error) {
	f.listCount++
	if f.err != nil {
		return nil, f.err
	}
	return f.instances, nil
}

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 1 || em[0] != EvidenceTypeID {
		t.Errorf("Emits = %v; want [%s]", em, EvidenceTypeID)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

func TestCollect_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{instances: []*gce.Instance{
		{
			Name:        "zeta-vm",
			Id:          2,
			SelfLink:    "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/instances/zeta-vm",
			Zone:        "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
			MachineType: "https://.../machineTypes/n1-standard-1",
			Status:      testStatusRunning,
			ServiceAccounts: []*gce.ServiceAccount{
				{Email: "12345-compute@developer.gserviceaccount.com"},
			},
		},
		{
			Name:        "alpha-vm",
			Id:          1,
			SelfLink:    "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west1-b/instances/alpha-vm",
			Zone:        "projects/p/zones/europe-west1-b",
			MachineType: "projects/p/zones/europe-west1-b/machineTypes/n2-standard-2",
			Status:      testStatusRunning,
			ServiceAccounts: []*gce.ServiceAccount{
				{Email: "custom@p.iam.gserviceaccount.com"},
			},
			NetworkInterfaces: []*gce.NetworkInterface{
				{AccessConfigs: []*gce.AccessConfig{{NatIP: "1.2.3.4"}}},
			},
			ShieldedInstanceConfig: &gce.ShieldedInstanceConfig{EnableSecureBoot: true},
			CanIpForward:           true,
			DeletionProtection:     true,
		},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "p1", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1", SlotName: "instances"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	// Sorted by ID (= selfLink): europe-west1-b/alpha-vm before
	// us-central1-a/zeta-vm.
	if records[0].ID != fake.instances[1].SelfLink || records[1].ID != fake.instances[0].SelfLink {
		t.Errorf("records not sorted by ID: got %v", []string{records[0].ID, records[1].ID})
	}
	assertCommonRecordFields(t, records, now)
	assertAlphaPayload(t, &records[0])
	assertZetaPayload(t, &records[1])
}

func assertCommonRecordFields(t *testing.T, records []core.EvidenceRecord, now time.Time) {
	t.Helper()
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
	}
}

func assertAlphaPayload(t *testing.T, rec *core.EvidenceRecord) {
	t.Helper()
	var alpha instancePayload
	if err := json.Unmarshal(rec.Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if alpha.UsesDefaultServiceAccount {
		t.Errorf("alpha.UsesDefaultServiceAccount = true; want false (custom SA)")
	}
	if !alpha.HasPublicIP {
		t.Errorf("alpha.HasPublicIP = false; want true")
	}
	if !alpha.ShieldedVMEnabled {
		t.Errorf("alpha.ShieldedVMEnabled = false; want true")
	}
	if !alpha.CanIPForward {
		t.Errorf("alpha.CanIPForward = false; want true")
	}
	if alpha.Zone != "europe-west1-b" {
		t.Errorf("alpha.Zone = %q", alpha.Zone)
	}
	// region must be the region (zone minus the trailing -<letter>), not
	// the zone itself.
	if alpha.Region != "europe-west1" {
		t.Errorf("alpha.Region = %q; want europe-west1 (region, not zone)", alpha.Region)
	}
	// monitoring_enabled must be OMITTED for GCP (no fabricated true), so
	// the monitoring policy's is_set guard scopes GCP instances out.
	if alpha.MonitoringEnabled != nil {
		t.Errorf("alpha.MonitoringEnabled = %v; want nil (GCP omits the field)", *alpha.MonitoringEnabled)
	}
	if alpha.MachineType != "n2-standard-2" {
		t.Errorf("alpha.MachineType = %q", alpha.MachineType)
	}
}

func assertZetaPayload(t *testing.T, rec *core.EvidenceRecord) {
	t.Helper()
	var zeta instancePayload
	if err := json.Unmarshal(rec.Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if !zeta.UsesDefaultServiceAccount {
		t.Errorf("zeta.UsesDefaultServiceAccount = false; want true (default Compute SA)")
	}
	if zeta.HasPublicIP {
		t.Errorf("zeta.HasPublicIP = true; want false")
	}
	if zeta.ShieldedVMEnabled {
		t.Errorf("zeta.ShieldedVMEnabled = true; want false (no config)")
	}
}

// TestCollect_SameNameInTwoZonesGetsDistinctIDs covers two VMs named
// "bastion" in different zones of one project. Instance names are unique
// per zone only, so each record must carry its own ID; otherwise the
// evaluator merges their violations and one resource_id waiver covers both.
func TestCollect_SameNameInTwoZonesGetsDistinctIDs(t *testing.T) {
	publicNIC := []*gce.NetworkInterface{{AccessConfigs: []*gce.AccessConfig{{NatIP: "34.1.2.3"}}}}
	const linkPrefix = "https://www.googleapis.com/compute/v1/projects/p/zones/"
	api := &fakeAPI{instances: []*gce.Instance{
		{Id: 111, Name: testBastion, Zone: "projects/p/zones/us-central1-a", SelfLink: linkPrefix + "us-central1-a/instances/bastion", Status: testStatusRunning, NetworkInterfaces: publicNIC},
		{Id: 222, Name: testBastion, Zone: "projects/p/zones/europe-west1-b", SelfLink: linkPrefix + "europe-west1-b/instances/bastion", Status: testStatusRunning, NetworkInterfaces: publicNIC},
	}}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: api, ProjectID: "p", Now: func() time.Time { return now }})
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d; want 2", len(recs))
	}
	if recs[0].ID == recs[1].ID {
		t.Fatalf("two VMs in different zones share record ID %q", recs[0].ID)
	}
	for i := range recs {
		var payload instancePayload
		if err := json.Unmarshal(recs[i].Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.ID != recs[i].ID || payload.Name != testBastion {
			t.Errorf("record %d: payload id=%q name=%q; want id=%q name=bastion", i, payload.ID, payload.Name, recs[i].ID)
		}
	}

	// The same clause as iso27001.8.22.no_public_compute_instances.
	pp := planner.PlannedPolicy{
		Spec: core.Policy{
			ID:           "p1",
			Controls:     []core.ControlRef{{ControlID: "A.8.22"}},
			Severity:     core.SeverityHigh,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots:        map[string]core.Slot{"s": {Accepts: []string{EvidenceTypeID}, Cardinality: core.SlotOneOrMore, Required: true}},
			PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot:         "s",
				Quantifier:   core.QuantifierAll,
				Filter:       &core.PassWhenCondition{Op: "eq", Field: "payload.is_running", Value: true},
				Condition:    &core.PassWhenCondition{Op: "eq", Field: "payload.has_public_ip", Value: false},
				ViolationMsg: "instance {{.payload.name}} has a public IP address",
			}}},
		},
		Parameters:     map[string]any{},
		ShouldEvaluate: true,
	}
	evaluate := func() *core.PolicyResult {
		t.Helper()
		res, err := evaluator.Evaluate(context.Background(), &evaluator.Input{
			Plan:            &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
			RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{"p1": {"s": recs}},
			Now:             now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return &res[0]
	}
	if r := evaluate(); r.ResourcesEvaluated != 2 || r.ResourcesFailed != 2 || len(r.Violations) != 2 {
		t.Errorf("both public VMs fail: got evaluated=%d failed=%d violations=%d; want 2/2/2",
			r.ResourcesEvaluated, r.ResourcesFailed, len(r.Violations))
	}

	// A waiver for the us-central1-a VM must not waive the europe-west1-b one.
	pp.Exceptions = []*planner.Exception{{State: core.StatusWaived, ResourceID: api.instances[0].SelfLink, Reason: "approved jump host"}}
	if r := evaluate(); r.Status != core.StatusFail {
		t.Errorf("waiver for one VM: status = %q; want fail (the other zone's public VM is not waived)", r.Status)
	}
}

// TestCollect_IDFallsBackToNameWithoutSelfLink keeps the ID stable for an
// instance without a selfLink, which the API never returns.
func TestCollect_IDFallsBackToNameWithoutSelfLink(t *testing.T) {
	p := New(Options{API: &fakeAPI{instances: []*gce.Instance{{Name: "a"}}}})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].ID != "a" {
		t.Errorf("ID = %q; want a", records[0].ID)
	}
}

func TestCollect_NoInstances(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("len(records) = %d; want 0", len(records))
	}
}

func TestCollect_NilInstancesSkipped(t *testing.T) {
	fake := &fakeAPI{instances: []*gce.Instance{nil, {Name: "a"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("len(records) = %d; want 1", len(records))
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"ec2_instance"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ListInstancesError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "aggregated list instances") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{instances: []*gce.Instance{{Name: "a"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now-injected value")
	}
}

func TestUsesDefaultSA_LiteralDefault(t *testing.T) {
	if !usesDefaultSA([]string{"default"}, "p1") {
		t.Errorf("literal 'default' SA not detected")
	}
}

func TestUsesDefaultSA_CustomReturnsFalse(t *testing.T) {
	if usesDefaultSA([]string{"custom@p.iam.gserviceaccount.com"}, "p1") {
		t.Errorf("custom SA mis-detected as default")
	}
}

func TestShortName_HandlesEdgeCases(t *testing.T) {
	if shortName("") != "" {
		t.Errorf("empty input not preserved")
	}
	if shortName("no-slashes") != "no-slashes" {
		t.Errorf("no-slash input mangled")
	}
}

func TestNewFromGCP_SmokeTest(t *testing.T) {
	p, err := NewFromGCP(context.Background(), "proj-1")
	if err != nil {
		t.Logf("NewFromGCP errored (acceptable in CI without ADC): %v", err)
		return
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{instances: []*gce.Instance{{Name: "a"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listCount != 3 {
		t.Errorf("listCount = %d; want 3 (no caching across Collect calls per KISS-no-DRY)", fake.listCount)
	}
}
