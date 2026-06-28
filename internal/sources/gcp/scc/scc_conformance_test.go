package scc

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	securitycenter "google.golang.org/api/securitycenter/v1"
	sccsettings "google.golang.org/api/securitycenter/v1beta2"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// scc_conformance_test.go: gcp SCC L1+L2 (WU-2.11). Multi-client (securitycenter
// v1 findings + v1beta2 settings; one host, one cassette served by a shared
// replay client). Runs RunConformance per evidence type (records are sorted
// within a type, not across the 3 the plugin emits). Hand-authored: ETD + SHA
// enabled, one HIGH active misconfiguration finding.
func TestGCPSCCConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		rc := sourcetest.ReplayClient(t, "testdata/cassettes/scc")
		opts := []option.ClientOption{option.WithoutAuthentication(), option.WithEndpoint("https://securitycenter.googleapis.com"), option.WithHTTPClient(rc)}
		findings, err := securitycenter.NewService(context.Background(), opts...)
		if err != nil {
			t.Fatal(err)
		}
		settings, err := sccsettings.NewService(context.Background(), opts...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realSCC{findings: findings, settings: settings}, OrgID: "123", Now: func() time.Time { return fixedNow }})
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
	if len(threat) != 1 || len(sec) != 1 || len(vuln) != 1 {
		t.Fatalf("records: threat=%d sec=%d vuln=%d, want 1/1/1", len(threat), len(sec), len(vuln))
	}
	var v vulnFindingPayload
	if err := json.Unmarshal(vuln[0].Payload, &v); err != nil {
		t.Fatal(err)
	}
	if v.Severity != "HIGH" || v.Status != "ACTIVE" || !v.RemediationAvailable {
		t.Errorf("finding = %+v; want HIGH/ACTIVE with remediation", v)
	}
}
