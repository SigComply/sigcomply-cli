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
			Zone:        "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
			MachineType: "https://.../machineTypes/n1-standard-1",
			Status:      "RUNNING",
			ServiceAccounts: []*gce.ServiceAccount{
				{Email: "12345-compute@developer.gserviceaccount.com"},
			},
		},
		{
			Name:        "alpha-vm",
			Id:          1,
			Zone:        "projects/p/zones/europe-west1-b",
			MachineType: "projects/p/zones/europe-west1-b/machineTypes/n2-standard-2",
			Status:      "RUNNING",
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
	// Sorted by ID (= Name): alpha-vm before zeta-vm.
	if records[0].ID != "alpha-vm" || records[1].ID != "zeta-vm" {
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
