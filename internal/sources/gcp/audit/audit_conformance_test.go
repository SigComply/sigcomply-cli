package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	crmv3 "google.golang.org/api/cloudresourcemanager/v3"
	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// audit_conformance_test.go: gcp.audit_log_trail L1+L2 (WU-2.11). Multi-client
// (cloudresourcemanager v3 + logging v2) — one cassette, one shared replay
// client serving both endpoints (matched by URL). Hand-authored: all-services
// audit logging incl. data-access, with CMEK on the log router.
func TestGCPAuditConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		rc := sourcetest.ReplayClient(t, "testdata/cassettes/audit")
		crmSvc, err := crmv3.NewService(context.Background(),
			option.WithoutAuthentication(), option.WithEndpoint("https://cloudresourcemanager.googleapis.com"), option.WithHTTPClient(rc))
		if err != nil {
			t.Fatal(err)
		}
		logSvc, err := logging.NewService(context.Background(),
			option.WithoutAuthentication(), option.WithEndpoint("https://logging.googleapis.com"), option.WithHTTPClient(rc))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realAudit{crm: crmSvc, log: logSvc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("audit_log_trail records = %d, want 1", len(recs))
	}
	var p trailPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsEnabled || !p.DataAccessLoggingEnabled || !p.KMSEncrypted {
		t.Errorf("trail = %+v; want enabled, data-access logging, CMEK", p)
	}
}
