package entra

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// entra_passwordpolicy_test.go pins the one thing that makes this emitter
// honest: it says only what Graph said. Entra exposes exactly one password
// attribute — the per-domain validity period — and the tests below assert
// both halves of that: the value it CAN read is read correctly (including
// Microsoft's never-expires sentinel), and the attributes it cannot read
// leave no trace in the payload beyond not_configurable, which is a
// statement about the API surface rather than a measurement.
//
// The payloads are compared as decoded JSON maps rather than as structs,
// the way the Okta password-policy conformance test does, because half of
// what is being asserted is which keys are ABSENT — and a struct
// comparison cannot see the difference between "omitted" and "zero".

// Domain names the password-policy fixtures use. Microsoft's own
// documentation examples use contoso.com / fabrikam.com, and the
// tenant's initial domain is always <tenant>.onmicrosoft.com.
const (
	domainManaged    = "contoso.com"
	domainInitial    = "contoso.onmicrosoft.com"
	domainUnverified = "unverified.contoso.com"
	domainFederated  = "fabrikam.com"
)

// Payload keys, spelled once so an assertion cannot drift from the emitter
// by a typo that silently passes.
const (
	pwKeyID              = "id"
	pwKeyProvider        = "provider"
	pwKeyScope           = "scope"
	pwKeyMaxAgeDays      = "max_age_days"
	pwKeyNotConfigurable = "not_configurable"
)

// emittedPasswordPolicyKeys is the COMPLETE set of keys this plugin may
// ever write. Asserting the emitted key set against it (rather than
// spot-checking a few absences) is what makes "no fabricated default"
// testable as a property instead of as a list of the defaults someone
// happened to think of: Microsoft's documented minimum length of 8, the
// documented "3 of 4 character classes" complexity rule and the
// documented 90-day fallback for an unset validity period are all values
// read from a manual rather than from the tenant, and none of them has a
// key it could arrive under here.
var emittedPasswordPolicyKeys = map[string]bool{
	pwKeyID: true, pwKeyProvider: true, pwKeyScope: true,
	pwKeyMaxAgeDays: true, pwKeyNotConfigurable: true,
}

func acceptPasswordPolicy() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypePasswordPolicy}}
}

// passwordPolicyDomains is the standard fixture: one managed domain with a
// real expiry, the tenant's initial domain set to never expire, an
// unverified domain (which governs no sign-in), and a federated domain
// whose passwords Entra does not enforce at all.
func passwordPolicyDomains() []Domain {
	ninety, sixty, never := int32(90), int32(60), int32(passwordNeverExpiresSentinel)
	return []Domain{
		// Deliberately out of ID order to exercise the sort.
		{ID: domainUnverified, IsVerified: false, AuthenticationType: authTypeManaged, PasswordValidityPeriodInDays: &ninety},
		{ID: domainInitial, IsVerified: true, AuthenticationType: authTypeManaged, PasswordValidityPeriodInDays: &never},
		{ID: domainManaged, IsVerified: true, AuthenticationType: authTypeManaged, PasswordValidityPeriodInDays: &ninety},
		{ID: domainFederated, IsVerified: true, AuthenticationType: authTypeFederated, PasswordValidityPeriodInDays: &sixty},
	}
}

// decodePayloads decodes each record's payload into a map keyed by record ID.
func decodePayloads(t *testing.T, recs []core.EvidenceRecord) map[string]map[string]any {
	t.Helper()
	out := make(map[string]map[string]any, len(recs))
	for i := range recs {
		var p map[string]any
		if err := json.Unmarshal(recs[i].Payload, &p); err != nil {
			t.Fatalf("unmarshal payload of %s: %v", recs[i].ID, err)
		}
		out[recs[i].ID] = p
	}
	return out
}

func TestCollectPasswordPolicies_OneRecordPerVerifiedDomain(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{domains: passwordPolicyDomains()}
	p := New(Options{API: api, Tenant: testTenantID, Now: fixedNow})

	recs, err := p.Collect(context.Background(), acceptPasswordPolicy())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	gotIDs := make([]string, len(recs))
	for i := range recs {
		gotIDs[i] = recs[i].ID
		if recs[i].Type != EvidenceTypePasswordPolicy {
			t.Errorf("record %s Type = %q, want %q", recs[i].ID, recs[i].Type, EvidenceTypePasswordPolicy)
		}
		if recs[i].Scope == nil || recs[i].Scope.Account != testTenantID {
			t.Errorf("record %s Scope = %+v, want Account %q", recs[i].ID, recs[i].Scope, testTenantID)
		}
	}
	// An unverified domain is excluded for the same reason Okta's INACTIVE
	// policies are: it governs nobody, so grading the estate on it would be
	// a finding about a rule that is not in force.
	want := []string{domainManaged, domainInitial, domainFederated}
	sort.Strings(want)
	if !reflect.DeepEqual(gotIDs, want) {
		t.Fatalf("record IDs = %v, want %v (sorted, unverified domain excluded)", gotIDs, want)
	}
}

func TestCollectPasswordPolicies_MapsExpiryIncludingTheNeverExpiresSentinel(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{domains: passwordPolicyDomains()}
	p := New(Options{API: api, Now: fixedNow})

	recs, err := p.Collect(context.Background(), acceptPasswordPolicy())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := decodePayloads(t, recs)

	for _, tc := range []struct {
		name string
		id   string
		want map[string]any
	}{
		{
			// A configured 90-day validity period, read verbatim.
			name: "managed_domain_with_a_real_expiry",
			id:   domainManaged,
			want: map[string]any{
				pwKeyID: domainManaged, pwKeyProvider: passwordPolicyProvider, pwKeyScope: scopeDomain,
				pwKeyMaxAgeDays:      float64(90),
				pwKeyNotConfigurable: []any{notConfigurableMinLength, notConfigurableReuse, notConfigurableComplexity},
			},
		},
		{
			// Microsoft's documented encoding of "passwords never expire"
			// is Int32.MaxValue. The schema's encoding of the same fact is
			// max_age_days 0 ("an observed no-expiry, not unknown"), which
			// is also what AWS and Okta emit for it — so the sentinel is
			// translated here, in the plugin that owns vendor→canonical
			// mapping, and never reaches a clause as a 2-billion-day age.
			name: "never_expires_sentinel_becomes_the_schema_s_zero",
			id:   domainInitial,
			want: map[string]any{
				pwKeyID: domainInitial, pwKeyProvider: passwordPolicyProvider, pwKeyScope: scopeDomain,
				pwKeyMaxAgeDays:      float64(0),
				pwKeyNotConfigurable: []any{notConfigurableMinLength, notConfigurableReuse, notConfigurableComplexity},
			},
		},
		{
			// A federated domain's passwords are validated by the external
			// IdP, so Entra's validity period is not the rule in force and
			// emitting it would assert an expiry nobody enforces.
			name: "federated_domain_carries_no_expiry_claim",
			id:   domainFederated,
			want: map[string]any{
				pwKeyID: domainFederated, pwKeyProvider: passwordPolicyProvider, pwKeyScope: scopeDomain,
				pwKeyNotConfigurable: []any{notConfigurableMinLength, notConfigurableReuse, notConfigurableComplexity},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !reflect.DeepEqual(got[tc.id], tc.want) {
				t.Errorf("payload = %#v\nwant %#v", got[tc.id], tc.want)
			}
		})
	}
}

// A validity period Graph did not report must not become the 90 days
// Microsoft's documentation names as the fallback. That number describes
// the product, not this tenant, and a tenant may have changed it — which
// is exactly the difference between a default and a constant.
func TestCollectPasswordPolicies_UnreportedValidityPeriodIsAbsent(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{domains: []Domain{
		{ID: domainManaged, IsVerified: true, AuthenticationType: authTypeManaged, PasswordValidityPeriodInDays: nil},
	}}
	p := New(Options{API: api, Now: fixedNow})

	recs, err := p.Collect(context.Background(), acceptPasswordPolicy())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	got := decodePayloads(t, recs)[domainManaged]
	if v, ok := got[pwKeyMaxAgeDays]; ok {
		t.Errorf("max_age_days = %v; want the key absent (Graph reported no value)", v)
	}
}

// The property this whole emitter exists to keep: every key in the payload
// came from the Graph response. Microsoft's documented minimum length (8),
// its documented "3 of 4 character classes" complexity rule and its
// documented 90-day expiry fallback are all read from documentation rather
// than from the tenant, and signing one into an EvidenceEnvelope would
// assert a measurement that was never taken.
func TestCollectPasswordPolicies_EmitsNoFabricatedValue(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{domains: passwordPolicyDomains()}
	p := New(Options{API: api, Now: fixedNow})

	recs, err := p.Collect(context.Background(), acceptPasswordPolicy())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for id, payload := range decodePayloads(t, recs) {
		for k := range payload {
			if !emittedPasswordPolicyKeys[k] {
				t.Errorf("record %s carries key %q, which Graph cannot answer — "+
					"a value here would be read from documentation, not from the tenant", id, k)
			}
		}
		// not_configurable says "this API exposes no setting", so the value
		// it refers to must stay absent; a record carrying both would be
		// claiming a measurement and its own impossibility at once.
		for _, k := range []string{"min_length", "reuse_prevented", "reuse_prevention_count", "complexity_model"} {
			if _, ok := payload[k]; ok {
				t.Errorf("record %s sets %q alongside not_configurable", id, k)
			}
		}
	}
}

func TestCollect_PasswordPolicyErrorPropagates(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("Authorization_RequestDenied")
	p := New(Options{API: &fakeAPI{domainErr: wantErr}, Now: fixedNow})
	_, err := p.Collect(context.Background(), acceptPasswordPolicy())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Collect error = %v, want it to wrap %v", err, wantErr)
	}
}

// A slot that does not accept password_policy must not trigger the call:
// GET /domains needs its own Graph permission (Domain.Read.All), and an
// estate that never asked for a password policy should not fail a run on a
// permission it had no reason to consent to.
func TestCollect_DoesNotListDomainsForOtherTypes(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{users: []User{{ID: userIDBob, UPN: emailBob}}}
	p := New(Options{API: api, Now: fixedNow})
	if _, err := p.Collect(context.Background(), acceptDirectoryUser()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if api.domainCalls != 0 {
		t.Errorf("ListDomains called %d times for a directory_user slot, want 0", api.domainCalls)
	}
}
