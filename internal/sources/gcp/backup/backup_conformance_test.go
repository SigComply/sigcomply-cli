package backup

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	backupdr "google.golang.org/api/backupdr/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// backup_conformance_test.go: gcp.backup_plan L1+L2 (WU-2.11). Hand-authored:
// one active Backup-and-DR plan with a 30-day retention rule.
func TestGCPBackupConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := backupdr.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/plans", "https://backupdr.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realBackupDR{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"backup_plan.retention_days", "backup_plan.covers_resource_types"},
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
