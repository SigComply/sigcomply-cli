package rds

import (
	"encoding/json"
	"testing"
	"time"

	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// rds_conformance_test.go: aws.managed_database_instance L1+L2 (WU-2.3). The
// cassette is hand-authored (account has no RDS): canned XML served via httptest
// at record time so the SDK's real request bodies are captured, then the
// endpoint URL was rewritten to the real RDS host. One encrypted, backup-on,
// deletion-protected postgres instance whose parameter group enforces SSL.
func TestRDSConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client := awsrds.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/instances"))
		return New(Options{API: client, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"managed_database_instance.engine",
			"managed_database_instance.engine_version",
			"managed_database_instance.ssl_required",
			"managed_database_instance.kms_key_id",
		},
	})
	if len(recs) != 1 {
		t.Fatalf("managed_database_instance records = %d, want 1", len(recs))
	}
	var p instancePayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.StorageEncrypted || !p.BackupEnabled || !p.DeletionProtection {
		t.Errorf("instance = %+v; want encrypted, backup-on, deletion-protected", p)
	}
	if p.SSLRequired == nil || !*p.SSLRequired {
		t.Errorf("ssl_required = %v, want true", p.SSLRequired)
	}
}
