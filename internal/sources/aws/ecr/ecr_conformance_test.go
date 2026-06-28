package ecr

import (
	"encoding/json"
	"testing"
	"time"

	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// ecr_conformance_test.go: aws.container_registry L1+L2 (WU-2.4). Cassette
// recorded against a repo with scan-on-push + IMMUTABLE tags.
func TestECRConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awsecr.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/repositories"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("container_registry records = %d, want 1", len(recs))
	}
	var p registryPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.ScanOnPushEnabled || !p.ImageImmutabilityEnabled || !p.EncryptionEnabled || p.IsPublic {
		t.Errorf("registry = %+v; want scan-on-push, immutable, encrypted, private", p)
	}
}
