package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// srcOkta is the Okta source identifier — bound here so the goconst
// linter doesn't flag the repeated literal across the planner tests.
const srcOkta = "okta"

type stubSource struct {
	id    string
	emits []string
}

func (s *stubSource) ID() string                                 { return s.id }
func (s *stubSource) Emits() []string                            { return s.emits }
func (s *stubSource) Init(context.Context, map[string]any) error { return nil }
func (s *stubSource) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, nil
}

func registerSource(t *testing.T, set *registry.Set, id string, emits ...string) {
	t.Helper()
	if err := set.Sources.Register(&stubSource{id: id, emits: emits}); err != nil {
		t.Fatalf("register %s: %v", id, err)
	}
}

func TestResolveBindings_ExactlyOne_AllowsAtMostOne(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "directory_user")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user"}, Cardinality: core.SlotExactlyOne, Required: true},
		},
	}
	// Zero bindings is allowed (deferred-source model: the policy plans
	// cleanly and is skipped at evaluation time). No configured sources,
	// so auto-binding has nothing to bind.
	bindings, err := resolveBindings(policy, map[string][]spec.BindingEntry{"u": nil}, set.Sources, nil)
	if err != nil {
		t.Fatalf("zero bindings should be allowed; got %v", err)
	}
	if len(bindings["u"]) != 0 {
		t.Errorf("expected empty bindings; got %v", bindings["u"])
	}
	// Two bindings for exactly-one is still a configuration error.
	_, err = resolveBindings(policy, map[string][]spec.BindingEntry{
		"u": {{Source: "aws.iam"}, {Source: "aws.iam"}},
	}, set.Sources, nil)
	if err == nil || !strings.Contains(err.Error(), "at most 1 binding, got 2") {
		t.Errorf("want at-most-1 error; got %v", err)
	}
}

func TestResolveBindings_AtMostOne(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "directory_user")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user"}, Cardinality: core.SlotAtMostOne, Required: false},
		},
	}
	// Zero is fine.
	if _, err := resolveBindings(policy, map[string][]spec.BindingEntry{"u": nil}, set.Sources, nil); err != nil {
		t.Errorf("at-most-one with zero bindings: %v", err)
	}
	// Two is not.
	_, err := resolveBindings(policy, map[string][]spec.BindingEntry{
		"u": {{Source: "aws.iam"}, {Source: "aws.iam"}},
	}, set.Sources, nil)
	if err == nil || !strings.Contains(err.Error(), "at most 1 binding") {
		t.Errorf("want at-most-one error; got %v", err)
	}
}

func TestResolveBindings_Optional(t *testing.T) {
	set := registry.NewSet()
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOptional, Required: false},
		},
	}
	bindings, err := resolveBindings(policy, nil, set.Sources, nil)
	if err != nil {
		t.Fatalf("optional with zero bindings: %v", err)
	}
	if len(bindings["u"]) != 0 {
		t.Errorf("expected empty bindings; got %v", bindings["u"])
	}
}

// TestAutoBind_NoExplicitBinding_BindsConfiguredSource is the core
// substitutability guarantee: configuring a source under sources: is
// enough to bind every policy slot that can consume it, with no
// bindings: block written by the operator.
func TestAutoBind_NoExplicitBinding_BindsConfiguredSource(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "directory_user")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true},
		},
	}
	// No bindings: entry at all; aws.iam is configured under sources:.
	bindings, err := resolveBindings(policy, nil, set.Sources, map[string]map[string]any{"aws.iam": {}})
	if err != nil {
		t.Fatalf("auto-bind: %v", err)
	}
	got := bindings["u"]
	if len(got) != 1 || got[0].SourceID != "aws.iam" {
		t.Fatalf("auto-bind result = %+v; want one binding to aws.iam", got)
	}
	if len(got[0].AcceptedTypes) != 1 || got[0].AcceptedTypes[0] != "directory_user" {
		t.Errorf("AcceptedTypes = %v; want [directory_user]", got[0].AcceptedTypes)
	}
}

// TestAutoBind_OneOrMore_UnionsAllMatchingSources: a one-or-more slot
// auto-binds every configured source that emits an accepted type, in
// sorted order for deterministic plans.
func TestAutoBind_OneOrMore_UnionsAllMatchingSources(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, srcOkta, "directory_user")
	registerSource(t, set, "aws.iam", "directory_user")
	registerSource(t, set, "aws.s3", "object_storage_bucket") // unrelated; must not bind
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true},
		},
	}
	bindings, err := resolveBindings(policy, nil, set.Sources,
		map[string]map[string]any{srcOkta: {}, "aws.iam": {}, "aws.s3": {}})
	if err != nil {
		t.Fatalf("auto-bind: %v", err)
	}
	got := bindings["u"]
	if len(got) != 2 {
		t.Fatalf("auto-bind result = %+v; want 2 bindings (aws.iam, okta)", got)
	}
	if got[0].SourceID != "aws.iam" || got[1].SourceID != srcOkta {
		t.Errorf("auto-bind order = [%s %s]; want sorted [aws.iam okta]", got[0].SourceID, got[1].SourceID)
	}
}

// TestAutoBind_ExplicitBindingOverridesAutoBind: when the operator names
// sources for a slot, auto-binding is suppressed for that slot — the
// explicit list is authoritative (the narrowing escape hatch).
func TestAutoBind_ExplicitBindingOverridesAutoBind(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, srcOkta, "directory_user")
	registerSource(t, set, "aws.iam", "directory_user")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true},
		},
	}
	// Both configured, but the operator narrows the slot to okta only.
	bindings, err := resolveBindings(policy,
		map[string][]spec.BindingEntry{"u": {{Source: srcOkta}}},
		set.Sources, map[string]map[string]any{srcOkta: {}, "aws.iam": {}})
	if err != nil {
		t.Fatalf("explicit override: %v", err)
	}
	got := bindings["u"]
	if len(got) != 1 || got[0].SourceID != srcOkta {
		t.Fatalf("explicit override result = %+v; want only okta", got)
	}
}

// TestAutoBind_SingleCardinalityAmbiguity_Errors: a single-source slot
// with two configured candidates can't be auto-resolved — the planner
// refuses to guess and tells the operator to add an explicit binding.
func TestAutoBind_SingleCardinalityAmbiguity_Errors(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, srcOkta, "directory_user")
	registerSource(t, set, "aws.iam", "directory_user")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user"}, Cardinality: core.SlotExactlyOne, Required: true},
		},
	}
	_, err := resolveBindings(policy, nil, set.Sources,
		map[string]map[string]any{srcOkta: {}, "aws.iam": {}})
	if err == nil || !strings.Contains(err.Error(), "add an explicit binding") {
		t.Fatalf("want ambiguity error asking for explicit binding; got %v", err)
	}
	// A single candidate auto-binds cleanly.
	bindings, err := resolveBindings(policy, nil, set.Sources,
		map[string]map[string]any{srcOkta: {}})
	if err != nil {
		t.Fatalf("single candidate should auto-bind; got %v", err)
	}
	if len(bindings["u"]) != 1 || bindings["u"][0].SourceID != srcOkta {
		t.Errorf("auto-bind result = %+v; want one binding to okta", bindings["u"])
	}
}

// TestAutoBind_UnconfiguredSourceNotBound: a source present in the
// registry but absent from sources: (e.g. a blank-imported builtin the
// operator never configured) must not be auto-bound — it has no creds.
func TestAutoBind_UnconfiguredSourceNotBound(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "directory_user")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true},
		},
	}
	// aws.iam is registered but NOT in configuredSources → no auto-bind.
	bindings, err := resolveBindings(policy, nil, set.Sources, map[string]map[string]any{})
	if err != nil {
		t.Fatalf("auto-bind: %v", err)
	}
	if len(bindings["u"]) != 0 {
		t.Errorf("expected no auto-bind for unconfigured source; got %+v", bindings["u"])
	}
}

func TestResolveBindings_ManualColonSuffixParsed(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "manual.pdf", "signed_document")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"doc": {Accepts: []string{"signed_document"}, Cardinality: core.SlotExactlyOne, Required: true},
		},
	}
	bindings, err := resolveBindings(policy, map[string][]spec.BindingEntry{
		"doc": {{Source: "manual.pdf:access_review_quarterly"}},
	}, set.Sources, nil)
	if err != nil {
		t.Fatalf("resolveBindings: %v", err)
	}
	if bindings["doc"][0].SourceID != "manual.pdf" {
		t.Errorf("SourceID = %q; want manual.pdf", bindings["doc"][0].SourceID)
	}
	if bindings["doc"][0].CatalogID != "access_review_quarterly" {
		t.Errorf("CatalogID = %q; want access_review_quarterly", bindings["doc"][0].CatalogID)
	}
}

func TestResolveBindings_RejectsBindingForUndeclaredSlot(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "directory_user")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true},
		},
	}
	_, err := resolveBindings(policy, map[string][]spec.BindingEntry{
		"u":            {{Source: "aws.iam"}},
		"phantom_slot": {{Source: "aws.iam"}},
	}, set.Sources, nil)
	if err == nil || !strings.Contains(err.Error(), "phantom_slot") {
		t.Errorf("want unknown-slot error; got %v", err)
	}
}

func TestEvidenceTypeFamily(t *testing.T) {
	cases := []struct{ in, want string }{
		{"directory_user", "directory_user"},
		{"directory_user.v2", "directory_user"},
		{"directory_user.v10", "directory_user"},
		{"object_storage_bucket", "object_storage_bucket"},
		{"gcp_service_account_key", "gcp_service_account_key"}, // underscores, no version
		{"foo.bar", "foo.bar"},                                 // ".bar" is not ".vN"
		{"foo.v", "foo.v"},                                     // bare "v" is not a version
		{"foo.v2x", "foo.v2x"},                                 // trailing non-digit
		{"foo.", "foo."},                                       // trailing dot
	}
	for _, tc := range cases {
		if got := evidenceTypeFamily(tc.in); got != tc.want {
			t.Errorf("evidenceTypeFamily(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestDetectCoverageGaps exercises the version-skew near-miss detector:
// an unbound required slot accepting only directory_user.v2 while a
// configured source emits directory_user (v1) is the canonical gap.
func TestDetectCoverageGaps(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, srcOkta, "directory_user", "okta_app")
	registerSource(t, set, "aws.iam", "directory_user.v2")
	registerSource(t, set, "aws.s3", "object_storage_bucket")

	v2Only := func() *core.Policy {
		return &core.Policy{
			ID: "p1",
			Slots: map[string]core.Slot{
				"users": {Accepts: []string{"directory_user.v2"}, Cardinality: core.SlotOneOrMore, Required: true},
			},
		}
	}

	t.Run("version skew flagged when slot unbound", func(t *testing.T) {
		gaps := detectCoverageGaps(v2Only(), map[string][]Binding{}, map[string]map[string]any{srcOkta: {}}, set.Sources)
		if len(gaps) != 1 {
			t.Fatalf("gaps = %d; want 1 (%+v)", len(gaps), gaps)
		}
		g := gaps[0]
		if g.Slot != "users" || g.Source != srcOkta {
			t.Errorf("gap = %+v; want slot=users source=okta", g)
		}
		if len(g.SourceEmits) != 1 || g.SourceEmits[0] != "directory_user" {
			t.Errorf("SourceEmits = %v; want [directory_user]", g.SourceEmits)
		}
	})

	t.Run("no gap when an exactly-accepted source is configured", func(t *testing.T) {
		// aws.iam emits directory_user.v2 exactly — the operator can bind
		// it; absence of a binding is a plain unbound slot, not skew.
		gaps := detectCoverageGaps(v2Only(), map[string][]Binding{}, map[string]map[string]any{srcOkta: {}, "aws.iam": {}}, set.Sources)
		if len(gaps) != 0 {
			t.Fatalf("gaps = %+v; want none (an exact emitter is configured)", gaps)
		}
	})

	t.Run("no gap when slot already bound", func(t *testing.T) {
		bound := map[string][]Binding{"users": {{SourceID: "aws.iam", AcceptedTypes: []string{"directory_user.v2"}}}}
		gaps := detectCoverageGaps(v2Only(), bound, map[string]map[string]any{srcOkta: {}}, set.Sources)
		if len(gaps) != 0 {
			t.Fatalf("gaps = %+v; want none (slot is bound)", gaps)
		}
	})

	t.Run("no gap for non-required slot", func(t *testing.T) {
		p := v2Only()
		s := p.Slots["users"]
		s.Required = false
		p.Slots["users"] = s
		gaps := detectCoverageGaps(p, map[string][]Binding{}, map[string]map[string]any{srcOkta: {}}, set.Sources)
		if len(gaps) != 0 {
			t.Fatalf("gaps = %+v; want none (slot not required)", gaps)
		}
	})

	t.Run("no gap when configured source is an unrelated family", func(t *testing.T) {
		gaps := detectCoverageGaps(v2Only(), map[string][]Binding{}, map[string]map[string]any{"aws.s3": {}}, set.Sources)
		if len(gaps) != 0 {
			t.Fatalf("gaps = %+v; want none (unrelated family)", gaps)
		}
	})

	t.Run("no gap when no sources configured", func(t *testing.T) {
		gaps := detectCoverageGaps(v2Only(), map[string][]Binding{}, nil, set.Sources)
		if len(gaps) != 0 {
			t.Fatalf("gaps = %+v; want none", gaps)
		}
	})
}

// TestResolveSlot_VersionSkewHint verifies the bound-source empty-
// intersection error names the version skew so the operator gets an
// actionable message rather than a bare type-mismatch.
func TestResolveSlot_VersionSkewHint(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, srcOkta, "directory_user")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"directory_user.v2"}, Cardinality: core.SlotOneOrMore, Required: true},
		},
	}
	_, err := resolveBindings(policy, map[string][]spec.BindingEntry{
		"u": {{Source: srcOkta}},
	}, set.Sources, nil)
	if err == nil || !strings.Contains(err.Error(), "version skew") {
		t.Fatalf("want version-skew hint in error; got %v", err)
	}
}

func TestSplitCommaList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"  a , b ,c  ", []string{"a", "b", "c"}},
		{"a,,b", []string{"a", "b"}},
	}
	for _, tc := range cases {
		got := SplitCommaList(tc.in)
		if !equalStringSlices(got, tc.want) {
			t.Errorf("SplitCommaList(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
