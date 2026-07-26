//go:build record

package gke

import (
	"context"
	"os"
	"testing"

	container "google.golang.org/api/container/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// gke_record_test.go records testdata/cassettes/clusters.yaml against the real
// Kubernetes Engine API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	# seed: a GKE cluster (setup-gcp full tier)
//	rm -f internal/sources/gcp/gke/testdata/cassettes/clusters.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordGKE ./internal/sources/gcp/gke/ -v
func TestRecordGKE(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := container.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/clusters", "https://container.googleapis.com")...)
	if err != nil {
		t.Fatalf("container client: %v", err)
	}
	p := New(Options{API: &realGKE{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a GKE cluster before recording")
	}
	t.Logf("recorded %d kubernetes_cluster record(s)", len(recs))
}
