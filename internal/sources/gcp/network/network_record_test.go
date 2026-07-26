//go:build record

package network

import (
	"context"
	"os"
	"testing"

	gce "google.golang.org/api/compute/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// network_record_test.go records testdata/cassettes/networks.yaml against the
// real Compute API (see the /compute/v1/ endpoint note in firewall_record_test.go).
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/network/testdata/cassettes/networks.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordNetwork ./internal/sources/gcp/network/ -v
func TestRecordNetwork(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := gce.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/networks", "https://compute.googleapis.com/compute/v1/")...)
	if err != nil {
		t.Fatalf("compute client: %v", err)
	}
	p := New(Options{API: &realNetwork{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — check the project VPC networks")
	}
	t.Logf("recorded %d network record(s)", len(recs))
}
