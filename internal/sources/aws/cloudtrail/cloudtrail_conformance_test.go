package cloudtrail

import (
	"encoding/json"
	"testing"
	"time"

	awsct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// cloudtrail_conformance_test.go: aws.audit_log_trail L1+L2 (WU-2.5). Cassette
// recorded against a provisioned multi-region trail with log-file validation.
func TestCloudTrailConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awsct.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/trails"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("audit_log_trail records = %d, want 1", len(recs))
	}
	var p trailPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsEnabled || !p.IsMultiRegion || !p.LogFileValidationEnabled {
		t.Errorf("trail = %+v; want enabled, multi-region, log-file-validation", p)
	}
}
