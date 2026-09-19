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
	newPlugin := func() core.SourcePlugin { return newCassettePlugin(t) }
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"directory_user.username", // UPN doubles as email
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

// newCassettePlugin builds the real adapter around the hand-authored cassette.
func newCassettePlugin(t *testing.T) core.SourcePlugin {
	t.Helper()
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	adapter := &realGraph{base: graphBaseURL, client: sourcetest.ReplayClient(t, "testdata/cassettes/directory"), cred: fakeCred{}}
	return New(Options{API: adapter, Now: func() time.Time { return fixedNow }})
}

// TestAzureEntraRosterConformance replays the roster interaction of the same
// hand-authored cassette (the literal /users roster projection URL): two
// members (one with employee fields, one disabled without a mailbox) and one
// guest, which must be excluded.
func TestAzureEntraRosterConformance(t *testing.T) {
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newCassettePlugin(t), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRosterEntry}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"roster_entry.is_service_account", // Entra users carry no service-account flag
			"roster_entry.employee_id",        // employeeId is optional per user
			"roster_entry.employee_type",      // employeeType is optional per user
		},
	})
	want := map[string]rosterPayload{
		"u-alice": {ID: "u-alice", Status: "active", Email: "alice@example.com", DisplayName: "Alice Admin",
			EmployeeID: "E100", EmployeeType: employeeTypeEmployee, SourceStatus: "enabled"},
		userIDCarol: {ID: userIDCarol, Status: "inactive", Email: "carol@example.com", DisplayName: "Carol Leaver",
			SourceStatus: "disabled"},
	}
	if len(recs) != len(want) {
		t.Fatalf("roster_entry records = %d, want %d (guest excluded)", len(recs), len(want))
	}
	for _, r := range recs {
		var p rosterPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p != want[r.ID] {
			t.Errorf("%s = %+v, want %+v", r.ID, p, want[r.ID])
		}
		if r.IdentityKey != p.Email {
			t.Errorf("%s IdentityKey = %q, want %q", r.ID, r.IdentityKey, p.Email)
		}
	}
}
