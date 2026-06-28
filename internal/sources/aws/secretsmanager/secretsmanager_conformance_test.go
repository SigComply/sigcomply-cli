package secretsmanager

import (
	"encoding/json"
	"testing"
	"time"

	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// secretsmanager_conformance_test.go: aws.secret L1+L2 (WU-2.3). Cassette
// recorded against a customer-KMS-encrypted, never-rotated secret.
func TestSecretsManagerConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client := awssm.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/secrets"))
		return New(Options{API: client, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newPlugin(),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"secret.last_rotated_days"},
	})
	if len(recs) != 1 {
		t.Fatalf("secret records = %d, want 1", len(recs))
	}
	var p secretPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.KMSEncrypted || !p.NeverRotated || p.RotationEnabled {
		t.Errorf("secret = %+v; want kms-encrypted, never-rotated, rotation off", p)
	}
}
