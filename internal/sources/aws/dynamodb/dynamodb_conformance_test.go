package dynamodb

import (
	"encoding/json"
	"testing"
	"time"

	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// dynamodb_conformance_test.go: aws.dynamodb L1+L2 (WU-2.3). DynamoDB is json
// protocol (DescribeTable/DescribeContinuousBackups carry X-Amz-Target).
func TestDynamoDBConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client := awsddb.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/tables"))
		return New(Options{API: client, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newPlugin(),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"nosql_table.stream_enabled"},
	})
	if len(recs) != 1 {
		t.Fatalf("nosql_table records = %d, want 1", len(recs))
	}
	var p tablePayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.EncryptionEnabled || !p.PointInTimeRecoveryEnabled || !p.DeletionProtection {
		t.Errorf("table = %+v; want encrypted, PITR, deletion-protected", p)
	}
}
