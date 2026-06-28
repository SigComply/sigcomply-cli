package vpc

import (
	"encoding/json"
	"testing"
	"time"

	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// vpc_conformance_test.go: aws.network L1+L2 (WU-2.6). Recorded against the
// account's default VPC (no flow logs).
func TestVPCConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awsec2.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/networks"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"network.region", "network.cidr_block"},
	})
	if len(recs) < 1 {
		t.Fatalf("network records = %d, want >= 1", len(recs))
	}
	var p networkPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsDefault || p.FlowLogsEnabled {
		t.Errorf("vpc = %+v; want default VPC without flow logs", p)
	}
}
