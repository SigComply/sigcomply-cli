//go:build record

package asset

import (
	"context"
	"os"
	"testing"

	cloudasset "google.golang.org/api/cloudasset/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// asset_record_test.go records testdata/cassettes/feeds.yaml against the real
// Cloud Asset Inventory API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/asset/testdata/cassettes/feeds.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordAsset ./internal/sources/gcp/asset/ -v
func TestRecordAsset(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := cloudasset.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/feeds", "https://cloudasset.googleapis.com")...)
	if err != nil {
		t.Fatalf("cloudasset client: %v", err)
	}
	p := New(Options{API: &realAsset{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed an Asset Inventory feed before recording")
	}
	t.Logf("recorded %d config_change_tracking record(s)", len(recs))
}
