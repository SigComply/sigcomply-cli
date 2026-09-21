package soc2_test

// password_policy_eval_test.go asserts what the four CC6.1 password
// policies actually decide, against synthetic records of both schema
// versions.
//
// ValidatePassWhen proves the clauses are well formed; it cannot prove
// they mean what the control means, and these four were rewritten for a
// reason that only shows up in the verdict. Two of them used to ask a
// question only an AWS-shaped source can answer — "are all four character
// classes required" and "is the history depth at least 24" — so a source
// that rates password strength on its own scale, or blocks reuse without
// disclosing a depth, could only ever be failed or fabricated. The clauses
// now ask what every source can answer truthfully.
//
// Three failure modes are load-bearing here and each has a case below:
// a record that cannot answer must not ERROR the policy (the evaluator
// errors on any reference to an absent field, so a missing is_set guard
// is exit 3 for the whole run); it must not be FAILED either (an unread
// setting is not a setting that is off); and when nothing in the slot can
// answer, the pass must be reported as vacuous rather than passing as if
// the estate had been examined.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

const (
	polMinLength  = "soc2.cc6.1.password_min_length_14"
	polExpiry     = "soc2.cc6.1.password_expiry_90d"
	polReuse      = "soc2.cc6.1.password_reuse_prevention"
	polComplexity = "soc2.cc6.1.password_complexity"

	typePasswordPolicyV1 = "password_policy"
	typePasswordPolicyV2 = "password_policy.v2"

	// The slot every automated SOC 2 policy declares, and the
	// password_policy payload keys these cases read or mutate.
	slotEvidence = "evidence"

	pwKeyID              = "id"
	pwKeyProvider        = "provider"
	pwKeyScope           = "scope"
	pwKeyMinLength       = "min_length"
	pwKeyMaxAgeDays      = "max_age_days"
	pwKeyReusePrevented  = "reuse_prevented"
	pwKeyReuseCount      = "reuse_prevention_count"
	pwKeyComplexityModel = "complexity_model"

	pwScopeAccount = "account"
	pwScopeDomain  = "domain"

	// The AWS singleton's record id happens to equal its scope; naming
	// both keeps the two readable apart.
	pwIDAccount   = "account"
	pwIDDomain    = "example.com"
	providerAWS   = "aws"
	providerEntra = "entra"
)

func pwRecord(t *testing.T, typeID, id string, payload map[string]any) core.EvidenceRecord {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return core.EvidenceRecord{
		Type: typeID, ID: id, Payload: body,
		SourceID: "aws.password_policy", CollectedAt: time.Unix(0, 0).UTC(),
	}
}

// v1Policy is a compliant password_policy.v1 record — the shape every
// estate on the previous schema emits. The four policies must keep
// deciding these exactly as they did before the reframing.
func v1Policy() map[string]any {
	return map[string]any{
		pwKeyID: pwIDAccount, pwKeyProvider: providerAWS,
		pwKeyMinLength: 14, pwKeyMaxAgeDays: 90, pwKeyReuseCount: 24,
		"requires_uppercase": true, "requires_lowercase": true,
		"requires_numbers": true, "requires_symbols": true,
	}
}

// v2PerClass is the same account expressed in v2 by the AWS emitter.
func v2PerClass() map[string]any {
	return map[string]any{
		pwKeyID: pwIDAccount, pwKeyProvider: providerAWS, pwKeyScope: pwScopeAccount, "precedence": 1,
		pwKeyMinLength: 14, pwKeyMaxAgeDays: 90,
		pwKeyReusePrevented: true, pwKeyReuseCount: 24,
		pwKeyComplexityModel: "per_class",
		"requires_uppercase": true, "requires_lowercase": true,
		"requires_numbers": true, "requires_symbols": true,
	}
}

// v2StrengthEnum is a Google-shaped record: a strength rating instead of
// character classes, and reuse as a bare boolean with no depth.
func v2StrengthEnum() map[string]any {
	return map[string]any{
		pwKeyID: "policies/ou-eng", pwKeyProvider: "google_workspace", pwKeyScope: "org_unit",
		pwKeyMinLength: 14, pwKeyMaxAgeDays: 90,
		pwKeyReusePrevented:  true,
		pwKeyComplexityModel: "strength_enum", "password_strength": "strong",
	}
}

func TestPasswordPolicies_BothSchemaVersionsDecideTheSame(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typeID  string
		payload map[string]any
	}{
		{"v1 record", typePasswordPolicyV1, v1Policy()},
		{"v2 per_class record", typePasswordPolicyV2, v2PerClass()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, id := range []string{polMinLength, polExpiry, polReuse, polComplexity} {
				got := evalPolicy(t, id, map[string][]core.EvidenceRecord{
					slotEvidence: {pwRecord(t, tc.typeID, pwIDAccount, tc.payload)},
				})
				if got.Status != core.StatusPass {
					t.Errorf("%s = %s (%v); want pass", id, got.Status, got.Violations)
				}
				if len(got.VacuousSlots()) > 0 {
					t.Errorf("%s passed vacuously over a record that answers it: %v", id, got.VacuousSlots())
				}
			}
		})
	}
}

// The reframed complexity clause, arm by arm. The strength_enum and fixed
// arms are the point of the rewrite: Google states in its own
// documentation that a strong password "doesn't need to have a specific
// number of characters of a specific type", so reading STRONG as four
// character-class booleans would fabricate a claim the vendor disclaims,
// and failing it would paint a red with no setting anywhere to turn on.
func TestPasswordComplexity_EveryComplexityModel(t *testing.T) {
	tests := []struct {
		name       string
		payload    map[string]any
		wantStatus core.PolicyStatus
		wantVacuum bool
	}{
		{
			name:       "per_class with every class required passes",
			payload:    v2PerClass(),
			wantStatus: core.StatusPass,
		},
		{
			name: "per_class missing one class fails",
			payload: mutate(v2PerClass(), func(m map[string]any) {
				m["requires_symbols"] = false
			}),
			wantStatus: core.StatusFail,
		},
		{
			name:       "strength_enum strong passes",
			payload:    v2StrengthEnum(),
			wantStatus: core.StatusPass,
		},
		{
			name: "strength_enum weak fails",
			payload: mutate(v2StrengthEnum(), func(m map[string]any) {
				m["password_strength"] = "weak"
			}),
			wantStatus: core.StatusFail,
		},
		{
			// A platform-enforced rule the tenant cannot weaken is a
			// control that IS enforced, whoever configured it.
			name: "platform-fixed complexity passes",
			payload: map[string]any{
				pwKeyID: pwIDDomain, pwKeyProvider: providerEntra, pwKeyScope: pwScopeDomain,
				pwKeyMaxAgeDays: 90, pwKeyComplexityModel: "fixed",
				"complexity_description": "three of four character classes, not tenant-configurable",
				"not_configurable":       []any{"min_length", "reuse", "complexity"},
			},
			wantStatus: core.StatusPass,
		},
		{
			// An account with no password policy at all. "none" is spelled
			// out precisely so it can fail here rather than being mistaken
			// for "the source did not say".
			name: "complexity_model none fails",
			payload: map[string]any{
				pwKeyID: pwIDAccount, pwKeyProvider: providerAWS, pwKeyScope: pwScopeAccount, "precedence": 1,
				pwKeyMinLength: 0, pwKeyMaxAgeDays: 0,
				pwKeyReusePrevented: false, pwKeyReuseCount: 0,
				pwKeyComplexityModel: "none",
			},
			wantStatus: core.StatusFail,
		},
		{
			// A source that cannot see the setting has not told us the
			// setting is off: out of scope, and the pass is reported as
			// having examined nothing.
			name: "a record that states no complexity answer is out of scope",
			payload: map[string]any{
				pwKeyID: pwIDDomain, pwKeyProvider: providerEntra, pwKeyScope: pwScopeDomain, pwKeyMaxAgeDays: 90,
			},
			wantStatus: core.StatusPass,
			wantVacuum: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evalPolicy(t, polComplexity, map[string][]core.EvidenceRecord{
				slotEvidence: {pwRecord(t, typePasswordPolicyV2, "p1", tc.payload)},
			})
			assertVerdict(t, &got, tc.wantStatus, tc.wantVacuum)
		})
	}
}

// Reuse is answered as a boolean because that is the only answer every
// vendor can give; the depth, where a vendor discloses one, refines it.
func TestPasswordReusePrevention_CountOrBoolean(t *testing.T) {
	tests := []struct {
		name       string
		typeID     string
		payload    map[string]any
		wantStatus core.PolicyStatus
		wantVacuum bool
	}{
		{
			name: "v1 depth 24 passes", typeID: typePasswordPolicyV1, payload: v1Policy(),
			wantStatus: core.StatusPass,
		},
		{
			name: "v1 depth 0 fails", typeID: typePasswordPolicyV1,
			payload:    mutate(v1Policy(), func(m map[string]any) { m[pwKeyReuseCount] = 0 }),
			wantStatus: core.StatusFail,
		},
		{
			// The accepted trade of the reframing, pinned so nobody
			// discovers it by accident: "prevented" no longer implies a
			// depth of 24. A second clause on the depth is a separate,
			// deferred decision — not a different verdict for the vendors
			// that disclose no depth.
			name: "v1 depth 1 now passes", typeID: typePasswordPolicyV1,
			payload:    mutate(v1Policy(), func(m map[string]any) { m[pwKeyReuseCount] = 1 }),
			wantStatus: core.StatusPass,
		},
		{
			name: "v2 boolean with no depth passes", typeID: typePasswordPolicyV2, payload: v2StrengthEnum(),
			wantStatus: core.StatusPass,
		},
		{
			name: "v2 boolean false fails", typeID: typePasswordPolicyV2,
			payload:    mutate(v2StrengthEnum(), func(m map[string]any) { m[pwKeyReusePrevented] = false }),
			wantStatus: core.StatusFail,
		},
		{
			name: "a record that answers neither is out of scope", typeID: typePasswordPolicyV2,
			payload: map[string]any{
				pwKeyID: pwIDDomain, pwKeyProvider: providerEntra, pwKeyScope: pwScopeDomain, pwKeyMaxAgeDays: 90,
			},
			wantStatus: core.StatusPass, wantVacuum: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evalPolicy(t, polReuse, map[string][]core.EvidenceRecord{
				slotEvidence: {pwRecord(t, tc.typeID, "p1", tc.payload)},
			})
			assertVerdict(t, &got, tc.wantStatus, tc.wantVacuum)
		})
	}
}

// min_length and expiry were not reframed — they only had to learn that
// v2 may not carry the field at all. A configured 0 is an observed "no
// minimum" and still fails; an absent one was never read and is not
// judged.
func TestPasswordLengthAndExpiry_AbsentIsNotZero(t *testing.T) {
	tests := []struct {
		name       string
		policyID   string
		payload    map[string]any
		wantStatus core.PolicyStatus
		wantVacuum bool
	}{
		{
			name: "configured minimum below the bar fails", policyID: polMinLength,
			payload:    mutate(v2PerClass(), func(m map[string]any) { m[pwKeyMinLength] = 8 }),
			wantStatus: core.StatusFail,
		},
		{
			name: "an unset minimum is not judged", policyID: polMinLength,
			payload:    mutate(v2PerClass(), func(m map[string]any) { delete(m, pwKeyMinLength) }),
			wantStatus: core.StatusPass, wantVacuum: true,
		},
		{
			name: "expiry beyond the bar fails", policyID: polExpiry,
			payload:    mutate(v2PerClass(), func(m map[string]any) { m[pwKeyMaxAgeDays] = 365 }),
			wantStatus: core.StatusFail,
		},
		{
			// 0 is the vendors' own encoding of "no expiry", which is a
			// deliberate configuration, not an absence.
			name: "no expiry passes", policyID: polExpiry,
			payload:    mutate(v2PerClass(), func(m map[string]any) { m[pwKeyMaxAgeDays] = 0 }),
			wantStatus: core.StatusPass,
		},
		{
			name: "an unset expiry is not judged", policyID: polExpiry,
			payload:    mutate(v2PerClass(), func(m map[string]any) { delete(m, pwKeyMaxAgeDays) }),
			wantStatus: core.StatusPass, wantVacuum: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evalPolicy(t, tc.policyID, map[string][]core.EvidenceRecord{
				slotEvidence: {pwRecord(t, typePasswordPolicyV2, "p1", tc.payload)},
			})
			assertVerdict(t, &got, tc.wantStatus, tc.wantVacuum)
		})
	}
}

// One slot, two sources, two schema versions — the substitutability
// promise. An estate running AWS and Google together must have every
// policy in force judged, each on the answer its own platform gave, and
// the one weak policy must be the one named.
func TestPasswordPolicies_MixedVersionSlot(t *testing.T) {
	weakGoogle := mutate(v2StrengthEnum(), func(m map[string]any) {
		m["id"] = "policies/ou-contractors"
		m["password_strength"] = "weak"
	})
	got := evalPolicy(t, polComplexity, map[string][]core.EvidenceRecord{
		slotEvidence: {
			pwRecord(t, typePasswordPolicyV1, pwIDAccount, v1Policy()),
			pwRecord(t, typePasswordPolicyV2, "policies/ou-contractors", weakGoogle),
		},
	})
	if got.Status != core.StatusFail {
		t.Fatalf("status = %s; want fail — one of the two policies in force is weak", got.Status)
	}
	if len(got.Violations) != 1 || got.Violations[0].ResourceID != "policies/ou-contractors" {
		t.Errorf("violations = %+v; want exactly the weak Google policy", got.Violations)
	}
}

// mutate copies a payload and applies a change, so each case starts from
// a record that passes everything and an unrelated regression cannot
// masquerade as the expected failure.
func mutate(base map[string]any, f func(map[string]any)) map[string]any {
	out := make(map[string]any, len(base))
	for k, v := range base {
		out[k] = v
	}
	f(out)
	return out
}

func assertVerdict(t *testing.T, got *core.PolicyResult, wantStatus core.PolicyStatus, wantVacuum bool) {
	t.Helper()
	// Called out separately from the status comparison: status=error is
	// exit 3 for the whole run, and it is what an unguarded read of an
	// optional field produces. A bare "want pass, got error" line would
	// not say that.
	if got.Status == core.StatusError && wantStatus != core.StatusError {
		t.Fatalf("status = error (%v) — a clause read a field the record does not carry; guard it with is_set", got.Diag)
	}
	if got.Status != wantStatus {
		t.Errorf("status = %s (%v); want %s", got.Status, got.Violations, wantStatus)
	}
	if vacuous := len(got.VacuousSlots()) > 0; vacuous != wantVacuum {
		t.Errorf("vacuous = %v (%v); want %v", vacuous, got.VacuousSlots(), wantVacuum)
	}
}
