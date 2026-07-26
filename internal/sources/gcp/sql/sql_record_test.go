//go:build record

package sql

import (
	"context"
	"os"
	"testing"

	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// sql_record_test.go records testdata/cassettes/instances.yaml against the real
// Cloud SQL Admin API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	# seed: a Cloud SQL instance (setup-gcp full tier)
//	rm -f internal/sources/gcp/sql/testdata/cassettes/instances.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordSQL ./internal/sources/gcp/sql/ -v
func TestRecordSQL(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := sqladmin.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/instances", "https://sqladmin.googleapis.com")...)
	if err != nil {
		t.Fatalf("sqladmin client: %v", err)
	}
	p := New(Options{API: &realSQL{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a Cloud SQL instance before recording")
	}
	t.Logf("recorded %d managed_database_instance record(s)", len(recs))
}
