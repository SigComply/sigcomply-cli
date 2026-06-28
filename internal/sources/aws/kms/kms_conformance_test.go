package kms

import (
	"encoding/json"
	"testing"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// kms_conformance_test.go: aws.kms L1+L2 (WU-2.3). json protocol with a per-key
// DescribeKey fan-out (same X-Amz-Target, distinct body) — exercises the body
// arm of AWSMatcher. The cassette holds one customer-managed key (rotation on)
// plus AWS-managed keys (rotation lookup skipped).
func TestKMSConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client := awskms.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/keys"))
		return New(Options{API: client, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newPlugin(),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"kms_key.arn"},
	})
	if len(recs) < 2 {
		t.Fatalf("kms_key records = %d, want >= 2 (customer + AWS-managed)", len(recs))
	}
	var customerWithRotation int
	for _, r := range recs {
		var p keyPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.IsCustomerManaged && p.RotationEnabled {
			customerWithRotation++
		}
	}
	if customerWithRotation != 1 {
		t.Errorf("customer-managed keys with rotation = %d, want 1", customerWithRotation)
	}
}
