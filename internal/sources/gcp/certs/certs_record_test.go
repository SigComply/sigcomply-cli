//go:build record

package certs

import (
	"context"
	"os"
	"testing"

	certificatemanager "google.golang.org/api/certificatemanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// certs_record_test.go records testdata/cassettes/certificates.yaml against the
// real Certificate Manager API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/certs/testdata/cassettes/certificates.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordCerts ./internal/sources/gcp/certs/ -v
func TestRecordCerts(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := certificatemanager.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/certificates", "https://certificatemanager.googleapis.com")...)
	if err != nil {
		t.Fatalf("certificatemanager client: %v", err)
	}
	p := New(Options{API: &realCertManager{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed certificates before recording")
	}
	t.Logf("recorded %d tls_certificate record(s)", len(recs))
}
