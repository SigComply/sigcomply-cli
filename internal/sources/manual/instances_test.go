package manual

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fanOutPlugin builds a plugin whose single catalog entry fans out over
// three vendors: two that owe an artifact and one approved exemption.
func fanOutPlugin(files map[string]InMemoryFile, instances []Instance) *Plugin {
	return New(Options{
		Reader: &InMemoryReader{Files: files},
		Bucket: testBucket,
		Prefix: defaultPrefix,
		Scheme: "s3",
		Catalog: map[string]CatalogEntry{
			testFanOutCatalogID: {
				EvidenceID:   testFanOutCatalogID,
				Cadence:      "annual",
				TemporalRule: "retrospective",
				GracePeriod:  30 * 24 * time.Hour,
				FanOut:       FanOutVendors,
				Instances:    instances,
			},
		},
	})
}

func fanOutReq() core.SlotRequest {
	return core.SlotRequest{
		PolicyID:      "soc2.cc9.2.vendor_assurance",
		AcceptedTypes: []string{EvidenceTypeID},
		SlotName:      "_manual",
		Params: map[string]any{
			keyCatalogID:   testFanOutCatalogID,
			keyPeriodID:    testPeriodID,
			keyPeriodStart: mustTime("2026-01-01T00:00:00Z"),
			keyPeriodEnd:   mustTime("2026-03-31T23:59:59Z"),
			keyNow:         mustTime("2026-02-01T00:00:00Z"),
		},
	}
}

var threeVendors = []Instance{
	{ID: testVendorID, Name: testVendorName, Tier: testTierCritical, Required: true},
	{ID: "initech", Name: "Initech", Tier: "high", Required: true},
	{ID: "zeta", Name: "Zeta", Tier: "low", Required: false,
		ExemptionReason: "Newsletter tool; no customer data.", ApprovedBy: "ciso@example.com"},
}

// The whole point of the fan-out: each vendor is scanned in its own
// folder, so a register with one missing document fails while the
// others are recorded as satisfied.
func TestCollect_FanOut_PerVendorFolders(t *testing.T) {
	uploaded := mustTime("2026-02-01T00:00:00Z")
	files := map[string]InMemoryFile{
		"manual/vendor_assurance.acme_cloud/2026-Q1/soc2.pdf": {Data: fakePDF(), UploadedAt: uploaded},
		// initech deliberately absent.
	}
	recs, err := fanOutPlugin(files, threeVendors).Collect(context.Background(), fanOutReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, recs)

	if m.InstancesTotal != 3 {
		t.Fatalf("InstancesTotal = %d; want 3", m.InstancesTotal)
	}
	// acme has its file, zeta is an approved exemption; only initech fails.
	if m.InstancesSatisfied != 2 {
		t.Fatalf("InstancesSatisfied = %d; want 2", m.InstancesSatisfied)
	}
	byID := map[string]instanceManifest{}
	for _, i := range m.Instances {
		byID[i.ID] = i
	}
	if !byID[testVendorID].Satisfied || !byID[testVendorID].FilePresent {
		t.Fatalf("acme_cloud = %+v; want satisfied and present", byID[testVendorID])
	}
	if byID["initech"].Satisfied || byID["initech"].FilePresent {
		t.Fatalf("initech = %+v; want unsatisfied and absent", byID["initech"])
	}
	// The exemption is recorded, not omitted — a decision somebody
	// signed must stay visible to an auditor.
	zeta := byID["zeta"]
	if !zeta.Satisfied || zeta.Required {
		t.Fatalf("zeta = %+v; want satisfied and not required", zeta)
	}
	if zeta.ExemptionReason == "" || zeta.ApprovedBy == "" {
		t.Fatalf("zeta exemption not recorded: %+v", zeta)
	}
	// The scalar summary is the conjunction over required instances.
	if m.FilePresent {
		t.Fatalf("FilePresent = true; want false while initech has no file")
	}
	// Each required instance points at its own folder.
	if !strings.Contains(byID[testVendorID].ExpectedURI, "vendor_assurance.acme_cloud/2026-Q1/") {
		t.Fatalf("acme_cloud.ExpectedURI = %q", byID[testVendorID].ExpectedURI)
	}
}

func TestCollect_FanOut_AllSatisfied(t *testing.T) {
	uploaded := mustTime("2026-02-01T00:00:00Z")
	files := map[string]InMemoryFile{
		"manual/vendor_assurance.acme_cloud/2026-Q1/a.pdf": {Data: fakePDF(), UploadedAt: uploaded},
		"manual/vendor_assurance.initech/2026-Q1/b.pdf":    {Data: fakePDF(), UploadedAt: uploaded},
	}
	recs, err := fanOutPlugin(files, threeVendors).Collect(context.Background(), fanOutReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, recs)
	if m.InstancesSatisfied != 3 || !m.FilePresent || !m.InTemporalWindow || !m.FileValid {
		t.Fatalf("manifest = %+v; want all three satisfied", m)
	}
}

// A declared coverage date far in the past is the single most common
// CC9.2 finding. The upload is current, so only the declared date can
// catch it.
func TestCollect_FanOut_StaleAssuranceFails(t *testing.T) {
	uploaded := mustTime("2026-02-01T00:00:00Z")
	files := map[string]InMemoryFile{
		"manual/vendor_assurance.acme_cloud/2026-Q1/old.pdf": {Data: fakePDF(), UploadedAt: uploaded},
	}
	stale := []Instance{
		{ID: testVendorID, Name: testVendorName, Tier: testTierCritical, Required: true,
			AssurancePeriodEnd: "2022-12-31"},
	}
	recs, err := fanOutPlugin(files, stale).Collect(context.Background(), fanOutReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, recs)
	inst := m.Instances[0]
	if inst.Satisfied {
		t.Fatalf("stale assurance was accepted: %+v", inst)
	}
	if !inst.FilePresent {
		t.Fatalf("file should still be recorded as present: %+v", inst)
	}
	joined := strings.Join(inst.ValidationFailures, " ")
	if !strings.Contains(joined, "assurance_out_of_date") {
		t.Fatalf("ValidationFailures = %v; want assurance_out_of_date", inst.ValidationFailures)
	}
}

func TestCollect_FanOut_CurrentAssurancePasses(t *testing.T) {
	uploaded := mustTime("2026-02-01T00:00:00Z")
	files := map[string]InMemoryFile{
		"manual/vendor_assurance.acme_cloud/2026-Q1/cur.pdf": {Data: fakePDF(), UploadedAt: uploaded},
	}
	fresh := []Instance{
		{ID: testVendorID, Name: testVendorName, Tier: testTierCritical, Required: true,
			AssurancePeriodEnd: "2025-12-31"},
	}
	recs, err := fanOutPlugin(files, fresh).Collect(context.Background(), fanOutReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, recs)
	if !m.Instances[0].Satisfied {
		t.Fatalf("current assurance rejected: %+v", m.Instances[0])
	}
}

func TestAssuranceStale(t *testing.T) {
	periodStart := mustTime("2026-01-01T00:00:00Z")
	for _, tc := range []struct {
		name     string
		declared string
		want     bool
	}{
		{"absent is not stale", "", false},
		{"recent", "2025-12-31", false},
		{"just inside the window", "2024-10-15", false},
		{"long expired", "2020-01-01", true},
		{"unparseable is not stale", "not-a-date", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := assuranceStale(tc.declared, periodStart)
			if got != tc.want {
				t.Fatalf("assuranceStale(%q) = %v; want %v", tc.declared, got, tc.want)
			}
			if got && reason == "" {
				t.Fatal("stale result carried no reason")
			}
		})
	}
}

// A zero period start (an unusual but reachable state) must not make
// every vendor stale.
func TestAssuranceStale_ZeroPeriodStart(t *testing.T) {
	if got, _ := assuranceStale("2000-01-01", time.Time{}); got {
		t.Fatal("zero period start produced a staleness verdict")
	}
}

func TestInstance_FolderID(t *testing.T) {
	i := Instance{ID: testVendorID}
	if got := i.FolderID(testFanOutCatalogID); got != "vendor_assurance.acme_cloud" {
		t.Fatalf("FolderID = %q", got)
	}
}

// An entry with no instances must behave exactly as it did before
// fan-out existed — this is what makes the feature additive.
func TestCollect_NoInstances_UnchangedShape(t *testing.T) {
	uploaded := mustTime("2026-02-01T00:00:00Z")
	files := map[string]InMemoryFile{
		"manual/vendor_assurance/2026-Q1/x.pdf": {Data: fakePDF(), UploadedAt: uploaded},
	}
	recs, err := fanOutPlugin(files, nil).Collect(context.Background(), fanOutReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, recs)
	if len(m.Instances) != 0 || m.InstancesTotal != 0 {
		t.Fatalf("instances leaked into a non-fan-out entry: %+v", m)
	}
	if !m.FilePresent || !m.FileValid {
		t.Fatalf("single-folder behavior changed: %+v", m)
	}
}
