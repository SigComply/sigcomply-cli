package cloudwatch

import (
	"encoding/json"
	"testing"
	"time"

	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// cloudwatch_conformance_test.go: aws.log_group L1+L2 (WU-2.5). Cassette
// recorded against a log group with a 30-day retention policy.
func TestCloudWatchConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := cwl.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/log_groups"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("log_group records = %d, want 1", len(recs))
	}
	var p logGroupPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.RetentionSet || p.RetentionDays != 30 {
		t.Errorf("log group = %+v; want retention set to 30 days", p)
	}
}
