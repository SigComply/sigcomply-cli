//go:build record

package secretmanager

import (
	"context"
	"os"
	"testing"

	secretmanager "google.golang.org/api/secretmanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// secretmanager_record_test.go records testdata/cassettes/secrets.yaml against the
// real Secret Manager API. Maintainer path (see gcptest.RecordLiveOptions):
//
//	gcloud auth application-default login
//	rm -f internal/sources/gcp/secretmanager/testdata/cassettes/secrets.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordSecretManager ./internal/sources/gcp/secretmanager/ -v
func TestRecordSecretManager(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	svc, err := secretmanager.NewService(context.Background(),
		gcptest.RecordLiveOptions(t, "testdata/cassettes/secrets", "https://secretmanager.googleapis.com")...)
	if err != nil {
		t.Fatalf("secretmanager client: %v", err)
	}
	p := New(Options{API: &realSM{svc: svc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a secret before recording")
	}
	t.Logf("recorded %d secret record(s)", len(recs))
}
