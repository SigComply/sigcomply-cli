package inspector

import (
	"encoding/json"
	"testing"
	"time"

	awsinsp "github.com/aws/aws-sdk-go-v2/service/inspector2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// inspector_conformance_test.go: aws.vulnerability_finding L1+L2 (WU-2.6).
// Hand-authored (findings need a scanned, vulnerable resource): one HIGH
// active CVE finding with a remediation.
func TestInspectorConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awsinsp.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/findings"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"vulnerability_finding.title", "vulnerability_finding.cve_id", "vulnerability_finding.score"},
	})
	if len(recs) != 1 {
		t.Fatalf("vulnerability_finding records = %d, want 1", len(recs))
	}
	var p findingPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Severity != "HIGH" || p.Status != "ACTIVE" || !p.RemediationAvailable || p.CVEID == "" {
		t.Errorf("finding = %+v; want HIGH/ACTIVE with remediation + CVE", p)
	}
}
