package iam

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	crm "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// iam_conformance_test.go: gcp.iam_binding L1+L2 (WU-2.7). Hand-authored policy
// (no live GCP cred): owner + viewer bindings → one record per (role, member).
func TestGCPIAMConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := crm.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/policy", "https://cloudresourcemanager.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realCRM{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 3 {
		t.Fatalf("iam_binding records = %d, want 3 (owner + 2 viewer members)", len(recs))
	}
	var broad int
	for _, r := range recs {
		var p bindingPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.IsBroadAdminRole {
			broad++
		}
	}
	if broad != 1 {
		t.Errorf("broad-admin bindings = %d, want 1 (roles/owner)", broad)
	}
}
