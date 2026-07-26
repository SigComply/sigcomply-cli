//go:build record

package audit

import (
	"context"
	"os"
	"testing"

	crmv3 "google.golang.org/api/cloudresourcemanager/v3"
	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
)

// audit_record_test.go records testdata/cassettes/audit.yaml against the real
// Resource Manager (v3) + Logging (v2) APIs. Both clients share ONE recording
// client (gcptest.RecordLiveClient), so a single cassette captures both — matched
// by URL on replay. Maintainer path:
//
//	gcloud auth application-default login
//	# seed: enable DATA_READ/DATA_WRITE audit logging on the project IAM policy
//	rm -f internal/sources/gcp/audit/testdata/cassettes/audit.yaml
//	GCP_TEST_PROJECT=<project> go test -tags record -run TestRecordAudit ./internal/sources/gcp/audit/ -v
func TestRecordAudit(t *testing.T) {
	project := os.Getenv("GCP_TEST_PROJECT")
	if project == "" {
		t.Skip("set GCP_TEST_PROJECT to record against a live project")
	}
	rc := gcptest.RecordLiveClient(t, "testdata/cassettes/audit")
	crmSvc, err := crmv3.NewService(context.Background(),
		option.WithoutAuthentication(), option.WithEndpoint("https://cloudresourcemanager.googleapis.com"), option.WithHTTPClient(rc))
	if err != nil {
		t.Fatalf("crm client: %v", err)
	}
	logSvc, err := logging.NewService(context.Background(),
		option.WithoutAuthentication(), option.WithEndpoint("https://logging.googleapis.com"), option.WithHTTPClient(rc))
	if err != nil {
		t.Fatalf("logging client: %v", err)
	}
	p := New(Options{API: &realAudit{crm: crmSvc, log: logSvc}, ProjectID: project})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records")
	}
	t.Logf("recorded %d audit_log_trail record(s)", len(recs))
}
