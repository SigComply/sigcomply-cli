package entra

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
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
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: conformanceOptionalUserFields,
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

// conformanceOptionalUserFields are the directory_user fields Graph's user
// projection does not carry.
var conformanceOptionalUserFields = []string{
	"directory_user.username", // UPN doubles as email
	"directory_user.mfa_factor_count", "directory_user.is_service_account",
	"directory_user.is_external", "directory_user.created_at",
}

// cassetteTenant is the tenant the cassette's /organization response
// reports. Nothing declares it in config — that is the point.
const cassetteTenant = "9f8a7b6c-5d4e-3f2a-1b0c-9d8e7f6a5b4c"

// newCassettePlugin builds the real adapter around the hand-authored
// cassette, through the same constructor production uses — so the replay
// exercises the /organization lookup and the records carry the tenant Graph
// reported rather than one a test made up.
func newCassettePlugin(t *testing.T) core.SourcePlugin {
	t.Helper()
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	adapter := &realGraph{base: graphBaseURL, client: sourcetest.ReplayClient(t, "testdata/cassettes/directory"), cred: fakeCred{}}
	p, err := newVerifiedPlugin(context.Background(), Options{
		API: adapter, Now: func() time.Time { return fixedNow },
	}, azcommon.Config{})
	if err != nil {
		t.Fatalf("newVerifiedPlugin: %v", err)
	}
	return p
}

// The observed tenant reaches the signed record, which is the whole
// provenance claim: an auditor reading one envelope learns which directory
// it came from, and that answer came from Graph, not from config.
func TestAzureEntraConformance_StampsTheObservedTenant(t *testing.T) {
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newCassettePlugin(t),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: conformanceOptionalUserFields,
	})
	for i := range recs {
		if recs[i].Scope == nil || recs[i].Scope.Account != cassetteTenant {
			t.Errorf("record %s scope = %+v; want Account %q", recs[i].ID, recs[i].Scope, cassetteTenant)
		}
	}
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

// TestAzureEntraPasswordPolicyConformance replays the /domains half of the
// same hand-authored cassette. The fixture is built from Microsoft's
// documented domain resource — the full property set Graph returns, not
// just the four fields this plugin decodes — because the point of an L2
// cassette is to exercise the real decoder against the real wire shape,
// including the properties it must ignore.
//
// Four domains, three records: a managed domain with a configured 90-day
// validity period, the tenant's initial domain set to Microsoft's
// never-expires sentinel, an unverified domain (excluded — it governs no
// sign-in), and a federated domain whose 60-day field is deliberately NOT
// emitted, because an external identity provider enforces that domain's
// passwords and Entra's number is not the rule in force.
func TestAzureEntraPasswordPolicyConformance(t *testing.T) {
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newCassettePlugin(t),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypePasswordPolicy}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: conformanceOptionalPasswordPolicyFields,
		WantScope:      &core.RecordScope{Account: cassetteTenant},
	})

	got := map[string]map[string]any{}
	for _, r := range recs {
		var p map[string]any
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		got[r.ID] = p
	}
	if _, ok := got[domainUnverified]; ok {
		t.Error("the unverified domain was emitted; nobody can sign in with it")
	}

	notConfigurable := []any{notConfigurableMinLength, notConfigurableReuse, notConfigurableComplexity}
	want := map[string]map[string]any{
		domainManaged: {
			pwKeyID: domainManaged, pwKeyProvider: passwordPolicyProvider, pwKeyScope: scopeDomain,
			pwKeyMaxAgeDays: float64(90), pwKeyNotConfigurable: notConfigurable,
		},
		domainInitial: {
			pwKeyID: domainInitial, pwKeyProvider: passwordPolicyProvider, pwKeyScope: scopeDomain,
			pwKeyMaxAgeDays: float64(0), pwKeyNotConfigurable: notConfigurable,
		},
		domainFederated: {
			pwKeyID: domainFederated, pwKeyProvider: passwordPolicyProvider, pwKeyScope: scopeDomain,
			pwKeyNotConfigurable: notConfigurable,
		},
	}
	if len(got) != len(want) {
		t.Fatalf("password_policy records = %d, want %d", len(got), len(want))
	}
	for id, w := range want {
		if !reflect.DeepEqual(got[id], w) {
			t.Errorf("%s payload = %#v\nwant %#v", id, got[id], w)
		}
	}
}

// conformanceOptionalPasswordPolicyFields are the password_policy.v2 fields
// an Entra record cannot carry. The list is long on purpose: it is the
// machine-readable form of "Graph answers one password question", and
// every entry here is a field another vendor fills and Microsoft does not
// expose — so a future Graph capability shows up as this list shrinking
// rather than as a silently-fabricated value.
var conformanceOptionalPasswordPolicyFields = []string{
	// A domain has no policy name separate from the domain itself, and
	// per-domain policies govern disjoint populations rather than
	// competing for one identity, so precedence is meaningless here (the
	// schema says to omit it in exactly that case).
	"password_policy.v2.name", "password_policy.v2.precedence",
	// Not tenant settings in Entra at all — recorded in not_configurable,
	// which is why their absence is structural rather than unread.
	"password_policy.v2.min_length",
	"password_policy.v2.reuse_prevented", "password_policy.v2.reuse_prevention_count",
	"password_policy.v2.complexity_model", "password_policy.v2.complexity_description",
	"password_policy.v2.requires_uppercase", "password_policy.v2.requires_lowercase",
	"password_policy.v2.requires_numbers", "password_policy.v2.requires_symbols",
	"password_policy.v2.password_strength",
	// MFA is a Conditional Access concept in Entra, not an attribute of
	// the password rule — the same exemption the AWS and Okta emitters take.
	"password_policy.v2.mfa_required",
	// Present on every managed domain; absent on a federated one, whose
	// passwords Entra does not enforce. The assertions above pin which is
	// which, so the exemption costs no coverage.
	"password_policy.v2.max_age_days",
}
