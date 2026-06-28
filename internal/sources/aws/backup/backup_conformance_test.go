package backup

import (
	"encoding/json"
	"testing"
	"time"

	awsbackup "github.com/aws/aws-sdk-go-v2/service/backup"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// backup_conformance_test.go: aws.backup_plan L1+L2 (WU-2.3). Cassette recorded
// against a plan with a retention rule (DeleteAfterDays=30).
func TestBackupConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client := awsbackup.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/plans"))
		return New(Options{API: client, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"backup_plan.retention_days",
			"backup_plan.covers_resource_types",
		},
	})
	if len(recs) != 1 {
		t.Fatalf("backup_plan records = %d, want 1", len(recs))
	}
	var p planPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsActive || !p.HasRetentionRule {
		t.Errorf("plan = %+v; want active with a retention rule", p)
	}
}
