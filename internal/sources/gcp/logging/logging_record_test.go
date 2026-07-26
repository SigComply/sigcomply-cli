//go:build record

package logging

import (
	"context"
	"os"
	"testing"

	logging "google.golang.org/api/logging/v2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// logging_record_test.go records testdata/cassettes/buckets.yaml against the real
// Cloud Logging API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/logging/testdata/cassettes/buckets.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordLogging ./internal/sources/gcp/logging/ -v
func TestRecordLogging(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := logging.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/buckets", "https://logging.googleapis.com")...)
	if err != nil {
		t.Fatalf("logging client: %v", err)
	}
	p := New(Options{API: &realLogging{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — check the project log buckets")
	}
	t.Logf("recorded %d log_group record(s)", len(recs))
}
