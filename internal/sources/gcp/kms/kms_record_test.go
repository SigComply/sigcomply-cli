//go:build record

package kms

import (
	"context"
	"os"
	"testing"

	cloudkms "google.golang.org/api/cloudkms/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// kms_record_test.go records testdata/cassettes/keys.yaml against the real Cloud
// KMS API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/kms/testdata/cassettes/keys.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordKMS ./internal/sources/gcp/kms/ -v
func TestRecordKMS(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := cloudkms.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/keys", "https://cloudkms.googleapis.com")...)
	if err != nil {
		t.Fatalf("kms client: %v", err)
	}
	p := New(Options{API: &realKMS{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a KMS keyring + key before recording")
	}
	t.Logf("recorded %d kms_key record(s)", len(recs))
}
