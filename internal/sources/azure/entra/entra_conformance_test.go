package entra

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// entra_conformance_test.go: azure.directory_user L1+L2 (WU-2.13). The MFA
// registration report (/reports/authenticationMethods/userRegistrationDetails)
// is Entra-ID-P2-gated in this tenant (RequestFromNonPremiumTenantOrB2CTenant),
// so the cassette is hand-authored (httptest-record) per the decision in
// CLAUDE.local.md rather than recorded live. Joins the report rows with /users:
// one admin with MFA + one standard user without.
func TestAzureEntraConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter := &realGraph{base: graphBaseURL, client: sourcetest.ReplayClient(t, "testdata/cassettes/directory"), cred: fakeCred{}}
		return New(Options{API: adapter, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"directory_user.mfa_factor_count", "directory_user.is_service_account",
			"directory_user.is_external", "directory_user.created_at",
		},
	})
	if len(recs) != 2 {
		t.Fatalf("directory_user records = %d, want 2", len(recs))
	}
	var admins, mfa int
	for _, r := range recs {
		var p userPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.IsAdmin {
			admins++
		}
		if p.MFAEnabled {
			mfa++
		}
	}
	if admins != 1 || mfa != 1 {
		t.Errorf("admins=%d mfa=%d, want 1/1", admins, mfa)
	}
}
