//go:build record

package firestore

import (
	"context"
	"os"
	"testing"

	firestore "google.golang.org/api/firestore/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// firestore_record_test.go records testdata/cassettes/databases.yaml against the
// real Firestore Admin API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/firestore/testdata/cassettes/databases.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordFirestore ./internal/sources/gcp/firestore/ -v
func TestRecordFirestore(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := firestore.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/databases", "https://firestore.googleapis.com")...)
	if err != nil {
		t.Fatalf("firestore client: %v", err)
	}
	p := New(Options{API: &realFirestore{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a Firestore database before recording")
	}
	t.Logf("recorded %d nosql_table record(s)", len(recs))
}
