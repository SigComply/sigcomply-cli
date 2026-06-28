package eks

import (
	"encoding/json"
	"testing"
	"time"

	awseks "github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// eks_conformance_test.go: aws.kubernetes_cluster L1+L2 (WU-2.4). Cassette is
// hand-authored (control plane is costly/slow): a private-endpoint cluster with
// control-plane logging and KMS secrets encryption.
func TestEKSConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awseks.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/clusters"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("kubernetes_cluster records = %d, want 1", len(recs))
	}
	var p clusterPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.SecretsEncryptionEnabled || !p.LoggingEnabled || !p.IsPrivateEndpoint {
		t.Errorf("cluster = %+v; want secrets-encryption, logging, private endpoint", p)
	}
}
