package core

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

// Fixture literals shared by the in-package core tests (policy state and
// cloud payload). goconst is package-scoped, so these live in one place
// rather than being re-declared per file.
const (
	testFrameworkSOC2 = "soc2"
	testSlotAccounts  = "accounts"
	testSlotRoster    = "roster"
	testFieldEmail    = "payload.email"

	// testTypeDirectoryUserV2 is the evidence type the sample policy's
	// slots accept and the digest fixtures version.
	testTypeDirectoryUserV2 = "directory_user.v2"
)

func f64(v float64) *float64 { return &v }

// samplePolicy returns a pass_when-driven policy exercising every field
// the canonical projection must cover: nested compound conditions, a
// filter, matches_in cross-slot fields, a min_percentage and a
// multi-clause body.
func samplePolicy() *Policy {
	return &Policy{
		ID:       "soc2.cc6.1.mfa_enforced_admins",
		Controls: []ControlRef{{Framework: testFrameworkSOC2, ControlID: "CC6.1"}},
		Severity: SeverityHigh,
		Cadence:  "daily",
		OnPush:   true,
		Slots: map[string]Slot{
			testSlotAccounts: {Accepts: []string{testTypeDirectoryUserV2, "iam_binding.v1"}, Cardinality: SlotOneOrMore, Required: true},
			testSlotRoster:   {Accepts: []string{testTypeDirectoryUserV2}, Cardinality: SlotOneOrMore, Required: true},
		},
		Parameters: map[string]ParameterSpec{
			"max_age_days": {Type: "int", Default: 90},
		},
		EvidenceMode: EvidenceModeAutomated,
		PassWhen: &PassWhenSpec{
			Clauses: []PassWhenClause{
				{
					Slot:       testSlotAccounts,
					Quantifier: QuantifierAll,
					Filter: &PassWhenCondition{
						Op: "all_of",
						Conditions: []*PassWhenCondition{
							{Op: "is_set", Field: "payload.is_admin"},
							{Op: "eq", Field: "payload.is_admin", Value: true},
						},
					},
					Condition: &PassWhenCondition{
						Op: "eq", Field: "payload.mfa_enabled", Value: true,
					},
					ViolationMsg: "admin {{.id}} has MFA disabled",
					IdentityKey:  "id",
				},
				{
					Slot:       testSlotAccounts,
					Quantifier: QuantifierCount,
					Condition: &PassWhenCondition{
						Op:          OpMatchesIn,
						Field:       testFieldEmail,
						InSlot:      testSlotRoster,
						RemoteField: testFieldEmail,
						Normalize:   NormalizeLowerTrim,
						Where:       &PassWhenCondition{Op: "eq", Field: "payload.active", Value: true},
					},
					MinPercentage: f64(95),
				},
			},
		},
	}
}

func sampleDigests() map[string]string {
	return map[string]string{
		testTypeDirectoryUserV2: "sha256:aaa",
		"iam_binding.v1":        "sha256:bbb",
	}
}

// mutate clones samplePolicy, applies fn, and returns the new hash.
func hashWith(t *testing.T, fn func(p *Policy)) string {
	t.Helper()
	p := samplePolicy()
	if fn != nil {
		fn(p)
	}
	return PolicyContentHash(p, sampleDigests())
}

// ---------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------

// TestPolicyContentHash_Deterministic runs the hash many times over a
// policy carrying several maps (slots, parameters, schema digests) plus
// a nested pass_when body. Go's map iteration order is randomized per
// range, so any unsorted map that leaked into the projection would
// surface here within a few hundred iterations.
func TestPolicyContentHash_Deterministic(t *testing.T) {
	want := PolicyContentHash(samplePolicy(), sampleDigests())
	if !strings.HasPrefix(want, "sha256:") {
		t.Fatalf("hash = %q; want a sha256: prefix", want)
	}
	for i := 0; i < 500; i++ {
		got := PolicyContentHash(samplePolicy(), sampleDigests())
		if got != want {
			t.Fatalf("iteration %d: hash = %q; want %q (map iteration order leaked into the projection)", i, got, want)
		}
	}
}

// TestPolicyContentHash_NilPolicy pins the documented nil contract.
func TestPolicyContentHash_NilPolicy(t *testing.T) {
	if got := PolicyContentHash(nil, sampleDigests()); got != "" {
		t.Errorf("hash of nil policy = %q; want \"\"", got)
	}
}

// TestPolicyContentHash_NilPassWhen proves a policy with no pass_when
// (a manual policy, or one using the rule: escape hatch) hashes without
// panicking and still discriminates other fields.
func TestPolicyContentHash_NilPassWhen(t *testing.T) {
	manual := &Policy{
		ID:           "soc2.cc1.1.board_charter",
		Controls:     []ControlRef{{Framework: testFrameworkSOC2, ControlID: "CC1.1"}},
		Severity:     SeverityMedium,
		Cadence:      "annual",
		EvidenceMode: EvidenceModeManual,
		CatalogEntry: "board_charter",
	}
	first := PolicyContentHash(manual, nil)
	if first == "" {
		t.Fatalf("hash of a nil-PassWhen policy = \"\"; want a real hash")
	}
	if second := PolicyContentHash(manual, nil); second != first {
		t.Errorf("hash not stable for a nil-PassWhen policy: %q vs %q", first, second)
	}

	// A nil PassWhen must not collide with a policy that has one.
	withPW := *manual
	withPW.PassWhen = &PassWhenSpec{Clauses: []PassWhenClause{{
		Slot: "files", Quantifier: QuantifierAll,
		Condition: &PassWhenCondition{Op: "is_set", Field: "payload.present"},
	}}}
	if got := PolicyContentHash(&withPW, nil); got == first {
		t.Errorf("nil PassWhen and a real PassWhen produced the same hash %q", got)
	}

	// An empty (non-nil) spec must not collide with nil either.
	empty := *manual
	empty.PassWhen = &PassWhenSpec{}
	if got := PolicyContentHash(&empty, nil); got == first {
		t.Errorf("nil PassWhen and an empty PassWhenSpec produced the same hash %q", got)
	}
}

// ---------------------------------------------------------------------
// pass_when participates in the hash
// ---------------------------------------------------------------------

// TestPolicyContentHash_PassWhenChangesRotateHash is the regression
// guard for the bug this table was written for: 100% of shipped
// policies are pass_when-driven, so a projection that omits pass_when
// lets any clause/operator/threshold edit keep its old hash — and the
// planner then carries the stale signed envelope forward until the next
// cadence boundary.
func TestPolicyContentHash_PassWhenChangesRotateHash(t *testing.T) {
	base := hashWith(t, nil)

	cases := []struct {
		name  string
		apply func(p *Policy)
	}{
		{"operator changed", func(p *Policy) {
			p.PassWhen.Clauses[0].Condition.Op = "neq"
		}},
		{"field changed", func(p *Policy) {
			p.PassWhen.Clauses[0].Condition.Field = "payload.mfa_required"
		}},
		{"value changed", func(p *Policy) {
			p.PassWhen.Clauses[0].Condition.Value = false
		}},
		{"threshold changed", func(p *Policy) {
			p.PassWhen.Clauses[1].MinPercentage = f64(90)
		}},
		{"threshold removed", func(p *Policy) {
			p.PassWhen.Clauses[1].MinPercentage = nil
		}},
		{"quantifier changed", func(p *Policy) {
			p.PassWhen.Clauses[0].Quantifier = QuantifierAny
		}},
		{"slot changed", func(p *Policy) {
			p.PassWhen.Clauses[0].Slot = testSlotRoster
		}},
		{"clause order swapped", func(p *Policy) {
			c := p.PassWhen.Clauses
			c[0], c[1] = c[1], c[0]
		}},
		{"clause removed", func(p *Policy) {
			p.PassWhen.Clauses = p.PassWhen.Clauses[:1]
		}},
		{"clause added", func(p *Policy) {
			p.PassWhen.Clauses = append(p.PassWhen.Clauses, PassWhenClause{
				Slot: testSlotRoster, Quantifier: QuantifierNone,
				Condition: &PassWhenCondition{Op: "eq", Field: "payload.active", Value: false},
			})
		}},
		{"filter removed", func(p *Policy) {
			p.PassWhen.Clauses[0].Filter = nil
		}},
		{"nested filter condition changed", func(p *Policy) {
			p.PassWhen.Clauses[0].Filter.Conditions[1].Value = false
		}},
		{"nested condition order swapped", func(p *Policy) {
			c := p.PassWhen.Clauses[0].Filter.Conditions
			c[0], c[1] = c[1], c[0]
		}},
		{"compound operator changed", func(p *Policy) {
			p.PassWhen.Clauses[0].Filter.Op = "any_of"
		}},
		{"matches_in slot changed", func(p *Policy) {
			p.PassWhen.Clauses[1].Condition.InSlot = testSlotAccounts
		}},
		{"matches_in remote field changed", func(p *Policy) {
			p.PassWhen.Clauses[1].Condition.RemoteField = "payload.upn"
		}},
		{"normalize cleared", func(p *Policy) {
			p.PassWhen.Clauses[1].Condition.Normalize = ""
		}},
		{"matches_in where changed", func(p *Policy) {
			p.PassWhen.Clauses[1].Condition.Where.Value = false
		}},
		{"matches_in where removed", func(p *Policy) {
			p.PassWhen.Clauses[1].Condition.Where = nil
		}},
		{"violation message changed", func(p *Policy) {
			p.PassWhen.Clauses[0].ViolationMsg = "admin {{.id}} is missing MFA"
		}},
		{"identity key changed", func(p *Policy) {
			p.PassWhen.Clauses[0].IdentityKey = testFieldEmail
		}},
	}

	seen := map[string]string{base: "baseline"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hashWith(t, tc.apply)
			if got == base {
				t.Fatalf("hash unchanged after %q; pass_when is not contributing to the content hash", tc.name)
			}
		})
		if prior, dup := seen[hashWith(t, tc.apply)]; dup {
			t.Errorf("%q collides with %q", tc.name, prior)
		}
		seen[hashWith(t, tc.apply)] = tc.name
	}
}

// TestPolicyContentHash_PassWhenOnlyDifferenceDiscriminates pins the
// narrow case directly: two policies identical in every other field,
// differing only in pass_when, must not share a hash.
func TestPolicyContentHash_PassWhenOnlyDifferenceDiscriminates(t *testing.T) {
	a := samplePolicy()
	b := samplePolicy()
	b.PassWhen.Clauses[0].Condition = &PassWhenCondition{
		Op: "gte", Field: "payload.key_age_days", Value: 90,
	}

	ha := PolicyContentHash(a, sampleDigests())
	hb := PolicyContentHash(b, sampleDigests())
	if ha == hb {
		t.Errorf("two policies differing only in pass_when share hash %q", ha)
	}
}

// TestPolicyContentHash_ValueTypeDiscriminates guards the loosest part
// of the projection: Value is an untyped `any` sourced from Go builders
// or YAML. A scalar, a list and a map that merely stringify alike must
// still hash apart.
func TestPolicyContentHash_ValueTypeDiscriminates(t *testing.T) {
	variants := map[string]any{
		"string": "90",
		"int":    90,
		// 90.5, not 90.0: JSON has a single number type, so an int 90
		// and a float 90.0 are the same token — and the same value to
		// the DSL. The projection is not expected to split them.
		"float": 90.5,
		"bool":  true,
		"list":  []any{"a", "b"},
		"map":   map[string]any{"a": 1, "b": 2},
		"nil":   nil,
	}
	seen := map[string]string{}
	for name, v := range variants {
		h := hashWith(t, func(p *Policy) { p.PassWhen.Clauses[0].Condition.Value = v })
		if prior, dup := seen[h]; dup {
			t.Errorf("Value %s collides with %s (hash %q)", name, prior, h)
		}
		seen[h] = name
	}

	// An inline map Value is hashed through encoding/json, which sorts
	// object keys — so the same map must hash identically every time.
	m := func() any { return map[string]any{"z": 1, "a": 2, "m": []any{3, 4}} }
	first := hashWith(t, func(p *Policy) { p.PassWhen.Clauses[0].Condition.Value = m() })
	for i := 0; i < 100; i++ {
		if got := hashWith(t, func(p *Policy) { p.PassWhen.Clauses[0].Condition.Value = m() }); got != first {
			t.Fatalf("map Value hashed non-deterministically at iteration %d", i)
		}
	}
}

// TestPolicyContentHash_UnmarshalableValueYieldsEmptyHash documents the
// one path that produces an empty hash from a non-nil policy: a Value
// encoding/json cannot represent. The planner must treat that as "due",
// which TestDecideEvaluation_EmptyHashForcesEvaluate covers.
func TestPolicyContentHash_UnmarshalableValueYieldsEmptyHash(t *testing.T) {
	p := samplePolicy()
	p.PassWhen.Clauses[0].Condition.Value = make(chan int)
	if got := PolicyContentHash(p, sampleDigests()); got != "" {
		t.Errorf("hash = %q; want \"\" for an unmarshalable Value", got)
	}
}

// ---------------------------------------------------------------------
// Pre-existing discrimination must survive the pass_when addition
// ---------------------------------------------------------------------

// TestPolicyContentHash_NonPassWhenChangesRotateHash re-pins the fields
// the projection already covered, so adding pass_when cannot silently
// drop one.
func TestPolicyContentHash_NonPassWhenChangesRotateHash(t *testing.T) {
	base := hashWith(t, nil)

	cases := []struct {
		name  string
		apply func(p *Policy)
	}{
		{"id", func(p *Policy) { p.ID = "soc2.cc6.1.other" }},
		{"control", func(p *Policy) { p.Controls[0].ControlID = "CC6.2" }},
		{"rule ref", func(p *Policy) { p.RuleRef = "rules.mfa.v1" }},
		{"severity", func(p *Policy) { p.Severity = SeverityLow }},
		{"cadence", func(p *Policy) { p.Cadence = "weekly" }},
		{"on_push", func(p *Policy) { p.OnPush = false }},
		{"slot accepts", func(p *Policy) {
			s := p.Slots[testSlotAccounts]
			s.Accepts = append(append([]string(nil), s.Accepts...), "service_account.v1")
			p.Slots[testSlotAccounts] = s
		}},
		{"slot required", func(p *Policy) {
			s := p.Slots[testSlotRoster]
			s.Required = false
			p.Slots[testSlotRoster] = s
		}},
		{"slot added", func(p *Policy) {
			p.Slots["extra"] = Slot{Accepts: []string{testTypeDirectoryUserV2}, Cardinality: SlotOneOrMore}
		}},
		{"parameter default", func(p *Policy) {
			ps := p.Parameters["max_age_days"]
			ps.Default = 30
			p.Parameters["max_age_days"] = ps
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hashWith(t, tc.apply); got == base {
				t.Errorf("hash unchanged after changing %s", tc.name)
			}
		})
	}
}

// TestPolicyContentHash_SchemaDigestChangesRotateHash keeps the
// schema-bump half of the contract alive: the hash must change when a
// referenced evidence-type schema's digest changes, even though the
// policy text is byte-identical.
func TestPolicyContentHash_SchemaDigestChangesRotateHash(t *testing.T) {
	p := samplePolicy()
	base := PolicyContentHash(p, sampleDigests())

	bumped := sampleDigests()
	bumped[testTypeDirectoryUserV2] = "sha256:ccc"
	if got := PolicyContentHash(p, bumped); got == base {
		t.Errorf("hash unchanged after a schema-digest bump")
	}

	added := sampleDigests()
	added["object_storage_bucket.v1"] = "sha256:ddd"
	if got := PolicyContentHash(p, added); got == base {
		t.Errorf("hash unchanged after adding a schema digest")
	}

	if got := PolicyContentHash(p, nil); got == base {
		t.Errorf("hash unchanged after dropping every schema digest")
	}

	// Digest map ordering must not matter.
	for i := 0; i < 200; i++ {
		if got := PolicyContentHash(p, sampleDigests()); got != base {
			t.Fatalf("schema-digest map iteration order leaked into the hash at iteration %d", i)
		}
	}
}

// TestCanonicalizePolicy_IncludesPassWhenKey asserts the projection's
// shape directly, so a future refactor that drops the key fails loudly
// rather than merely rotating every hash.
func TestCanonicalizePolicy_IncludesPassWhenKey(t *testing.T) {
	canon, ok := canonicalizePolicy(samplePolicy(), nil).(map[string]any)
	if !ok {
		t.Fatalf("canonicalizePolicy returned %T; want map[string]any", canonicalizePolicy(samplePolicy(), nil))
	}
	pw, present := canon["pass_when"]
	if !present {
		t.Fatalf("canonical projection has no \"pass_when\" key; keys present: %v", keysOf(canon))
	}
	if pw == nil {
		t.Fatalf("\"pass_when\" is nil for a policy that has a pass_when block")
	}

	// A nil PassWhen must still emit the key (as null) so the projection
	// shape is uniform across policies.
	p := samplePolicy()
	p.PassWhen = nil
	canonNil, ok := canonicalizePolicy(p, nil).(map[string]any)
	if !ok {
		t.Fatalf("canonicalizePolicy with nil PassWhen returned %T; want map[string]any", canonicalizePolicy(p, nil))
	}
	if v, present := canonNil["pass_when"]; !present || v != nil {
		t.Errorf("nil PassWhen: pass_when present=%v value=%v; want present=true value=nil", present, v)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
