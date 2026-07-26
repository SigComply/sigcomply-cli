//go:build record

package backup

import (
	"context"
	"os"
	"testing"

	backupdr "google.golang.org/api/backupdr/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// backup_record_test.go records testdata/cassettes/plans.yaml against the real
// Backup and DR API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	# seed: a backup vault + an active backup plan with a retention rule
//	rm -f internal/sources/gcp/backup/testdata/cassettes/plans.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordBackup ./internal/sources/gcp/backup/ -v
func TestRecordBackup(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := backupdr.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/plans", "https://backupdr.googleapis.com")...)
	if err != nil {
		t.Fatalf("backupdr client: %v", err)
	}
	p := New(Options{API: &realBackupDR{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a backup plan before recording")
	}
	t.Logf("recorded %d backup_plan record(s)", len(recs))
}
