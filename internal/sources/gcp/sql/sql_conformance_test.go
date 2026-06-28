package sql

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// sql_conformance_test.go: gcp.managed_database_instance L1+L2 (WU-2.7).
// Hand-authored: one REGIONAL postgres instance, SSL required, backups + PITR,
// no public IP, deletion protection.
func TestGCPSQLConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := sqladmin.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/instances", "https://sqladmin.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realSQL{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"managed_database_instance.kms_key_id"},
	})
	if len(recs) != 1 {
		t.Fatalf("managed_database_instance records = %d, want 1", len(recs))
	}
	var p instancePayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.SSLRequired || p.PubliclyAccessible || !p.BackupEnabled || !p.DeletionProtection {
		t.Errorf("instance = %+v; want SSL-required, private, backups, deletion-protected", p)
	}
}
