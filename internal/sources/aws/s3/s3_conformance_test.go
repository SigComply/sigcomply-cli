package s3

import (
	"encoding/json"
	"testing"
	"time"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// s3_conformance_test.go: aws.s3 L1+L2 (WU-2.3). Replays a cassette recorded
// against a provisioned bucket (SSE-KMS + versioning + public-access-block).
func TestS3Conformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client := awss3.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/buckets"))
		return New(Options{API: client, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"object_storage_bucket.region_or_location",
			"object_storage_bucket.kms_managed",
			"object_storage_bucket.kms_key_id",
			"object_storage_bucket.versioning_enabled",
			"object_storage_bucket.created_at",
		},
	})
	if len(recs) != 1 {
		t.Fatalf("object_storage_bucket records = %d, want 1", len(recs))
	}
	var p bucketPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.EncryptionAtRestEnabled || !p.PublicAccessBlocked || !p.VersioningEnabled {
		t.Errorf("bucket = %+v; want encrypted, public-access-blocked, versioned", p)
	}
}
