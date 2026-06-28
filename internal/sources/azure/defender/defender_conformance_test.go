package defender

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// defender_conformance_test.go: azure Defender for Cloud L1+L2 (WU-2.12).
// Hand-authored: two pricing plans (VMs Standard/P2, Storage Free) + one High
// sub-assessment finding. Three evidence types, run per type.
func TestAzureDefenderConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealDefender(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/defender"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	types := sourcetest.BuiltinEvidenceTypes(t)
	threat := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeThreatService}},
		EvidenceTypes: types, OptionalFields: []string{"threat_detection_service.region"},
	})
	sec := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeSecurityService}},
		EvidenceTypes: types,
	})
	vuln := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnFinding}},
		EvidenceTypes: types, OptionalFields: []string{"vulnerability_finding.title", "vulnerability_finding.cve_id", "vulnerability_finding.score"},
	})
	if len(threat) != 2 || len(sec) != 1 || len(vuln) != 1 {
		t.Fatalf("records: threat=%d sec=%d vuln=%d, want 2/1/1", len(threat), len(sec), len(vuln))
	}
	var v vulnFindingPayload
	if err := json.Unmarshal(vuln[0].Payload, &v); err != nil {
		t.Fatal(err)
	}
	if v.Severity != "HIGH" || !v.RemediationAvailable {
		t.Errorf("finding = %+v; want HIGH with remediation", v)
	}
}
