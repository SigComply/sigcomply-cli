//go:build record

package iam

import (
	"context"
	"os"
	"testing"

	crm "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// iam_record_test.go records testdata/cassettes/policy.yaml against the real
// Cloud Resource Manager API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/iam/testdata/cassettes/policy.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordIAM ./internal/sources/gcp/iam/ -v
func TestRecordIAM(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := crm.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/policy", "https://cloudresourcemanager.googleapis.com")...)
	if err != nil {
		t.Fatalf("crm client: %v", err)
	}
	p := New(Options{API: &realCRM{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — check the project IAM policy")
	}
	t.Logf("recorded %d iam_binding record(s)", len(recs))
}
