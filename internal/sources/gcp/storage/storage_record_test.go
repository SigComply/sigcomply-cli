//go:build record

package storage

import (
	"context"
	"os"
	"testing"

	gcs "cloud.google.com/go/storage"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// storage_record_test.go records testdata/cassettes/buckets.yaml against the REAL
// GCS API (WU-2.7 re-record). It is the maintainer path that replaces the
// hand-authored cassette with a genuine recording; the offline
// storage_conformance_test.go replays whatever this captures.
//
// Prerequisites (see gcptest.RecordLiveOptions):
//  1. Seed a bucket in the test project (uniform bucket-level access +
//     public-access-prevention + versioning; CMEK optional).
//  2. gcloud auth application-default login \
//     --impersonate-service-account=sigcomply-e2e-recorder@<project>.iam.gserviceaccount.com
//  3. rm -f testdata/cassettes/buckets.yaml   # record fresh, don't append
//  4. GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordBuckets \
//     ./internal/sources/gcp/storage/ -v
//
// Then scrub identifiers to the §4 placeholders, run `make check-fixtures`, and
// re-run the offline conformance test to confirm it replays green.
func TestRecordBuckets(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	client, err := gcs.NewClient(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/buckets", "https://storage.googleapis.com/storage/v1/")...)
	if err != nil {
		t.Fatalf("gcs client: %v", err)
	}
	p := New(Options{API: &realGCS{client: client}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 buckets — seed at least one bucket in the project before recording")
	}
	t.Logf("recorded %d bucket record(s) into testdata/cassettes/buckets.yaml", len(recs))
}
