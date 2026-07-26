//go:build record

package artifactregistry

import (
	"context"
	"os"
	"testing"

	artifactregistry "google.golang.org/api/artifactregistry/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// artifactregistry_record_test.go records testdata/cassettes/repositories.yaml
// against the real Artifact Registry API. Maintainer path (see
// gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/artifactregistry/testdata/cassettes/repositories.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordArtifactRegistry ./internal/sources/gcp/artifactregistry/ -v
func TestRecordArtifactRegistry(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := artifactregistry.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/repositories", "https://artifactregistry.googleapis.com")...)
	if err != nil {
		t.Fatalf("artifactregistry client: %v", err)
	}
	p := New(Options{API: &realAR{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed an Artifact Registry repo before recording")
	}
	t.Logf("recorded %d container_registry record(s)", len(recs))
}
