//go:build record

package firewall

import (
	"context"
	"os"
	"testing"

	gce "google.golang.org/api/compute/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// firewall_record_test.go records testdata/cassettes/firewalls.yaml against the
// real Compute API. Note the /compute/v1/ endpoint: the compute Discovery client
// puts the version in the base path, so the bare host (used elsewhere) hits the
// XML API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/firewall/testdata/cassettes/firewalls.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordFirewall ./internal/sources/gcp/firewall/ -v
func TestRecordFirewall(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := gce.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/firewalls", "https://compute.googleapis.com/compute/v1/")...)
	if err != nil {
		t.Fatalf("compute client: %v", err)
	}
	p := New(Options{API: &realFirewall{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — check the project firewall rules")
	}
	t.Logf("recorded %d firewall_rule record(s)", len(recs))
}
