package ec2

import (
	"encoding/json"
	"testing"
	"time"

	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// ec2_conformance_test.go: aws.compute_instance L1+L2 (WU-2.4). Cassette
// recorded against a provisioned t3.micro (encrypted root, public IP).
func TestEC2Conformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awsec2.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/instances"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"compute_instance.metadata_service_hardened",
			"compute_instance.region",
		},
	})
	if len(recs) != 1 {
		t.Fatalf("compute_instance records = %d, want 1", len(recs))
	}
	var p instancePayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsRunning || !p.HasPublicIP || !p.RootVolumeEncrypted {
		t.Errorf("instance = %+v; want running, public IP, encrypted root", p)
	}
}
