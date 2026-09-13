package planner

import (
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// lookupSourcePlugin is exact, including for instance keys. Every
// configured source is registered under its exact key, so a miss means
// the key names nothing real. A base-ID fallback would make a typo'd
// instance silently resolve to a different instance's plugin —
// collecting the wrong account and then labeling the evidence with the
// typo'd name.
func TestLookupSourcePlugin_IsExact(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "directory_user")
	registerSource(t, set, "aws.iam[backup]", "directory_user")

	if p := lookupSourcePlugin(set.Sources, "aws.iam"); p == nil {
		t.Fatal("exact key lookup failed")
	}
	if p := lookupSourcePlugin(set.Sources, "aws.iam[backup]"); p == nil {
		t.Error("a registered instance key must resolve")
	} else if p.ID() != "aws.iam[backup]" {
		t.Errorf("instance resolved to %q; want aws.iam[backup]", p.ID())
	}
	if p := lookupSourcePlugin(set.Sources, "aws.iam[typo]"); p != nil {
		t.Error("an unregistered instance must NOT fall back to the base plugin")
	}
	if p := lookupSourcePlugin(set.Sources, "no.such.source"); p != nil {
		t.Error("unknown source should return nil")
	}
}

// enforceCardinality rejects an unknown cardinality value (the default
// branch — a malformed slot that escaped spec validation).
func TestEnforceCardinality_UnknownCardinalityErrors(t *testing.T) {
	slot := &core.Slot{Cardinality: core.SlotCardinality("triple")}
	if err := enforceCardinality("p1", "s1", slot, 1); err == nil ||
		!strings.Contains(err.Error(), "unknown cardinality") {
		t.Errorf("want unknown-cardinality error; got %v", err)
	}
}

// enforceCardinality allows zero bindings for a required exactly-one
// slot (deferred-source model: plans cleanly, skipped at evaluation).
func TestEnforceCardinality_ZeroBindingsAllowed(t *testing.T) {
	for _, c := range []core.SlotCardinality{
		core.SlotExactlyOne, core.SlotAtMostOne, core.SlotOneOrMore, core.SlotOptional,
	} {
		slot := &core.Slot{Cardinality: c}
		if err := enforceCardinality("p1", "s1", slot, 0); err != nil {
			t.Errorf("cardinality %q with 0 bindings should be allowed; got %v", c, err)
		}
	}
}

// enforceCardinality rejects >1 binding on a single-source slot.
func TestEnforceCardinality_TooManyForSingle(t *testing.T) {
	for _, c := range []core.SlotCardinality{core.SlotExactlyOne, core.SlotAtMostOne} {
		slot := &core.Slot{Cardinality: c}
		if err := enforceCardinality("p1", "s1", slot, 2); err == nil {
			t.Errorf("cardinality %q with 2 bindings should error", c)
		}
	}
}

// resolveSlot rejects a slot whose Accepts list is empty — a policy
// authoring error caught at plan time.
func TestResolveSlot_EmptyAcceptsErrors(t *testing.T) {
	set := registry.NewSet()
	slot := &core.Slot{Accepts: nil, Cardinality: core.SlotOneOrMore}
	_, err := resolveSlot("p1", "s1", slot, nil, set.Sources, nil)
	if err == nil || !strings.Contains(err.Error(), "Accepts is empty") {
		t.Errorf("want empty-Accepts error; got %v", err)
	}
}

// policyMatchesControl matches when ANY of the policy's multi-framework
// controls is in the wanted set, and returns false otherwise.
func TestPolicyMatchesControl(t *testing.T) {
	policy := &core.Policy{
		Controls: []core.ControlRef{
			{Framework: "soc2", ControlID: "SOC2.CC6.1"},
			{Framework: "iso27001", ControlID: "A.9.4.2"},
		},
	}
	if !policyMatchesControl(policy, []string{"A.9.4.2"}) {
		t.Error("should match the ISO control")
	}
	if !policyMatchesControl(policy, []string{"X", "SOC2.CC6.1"}) {
		t.Error("should match when one wanted control intersects")
	}
	if policyMatchesControl(policy, []string{"SOC2.CC9.9"}) {
		t.Error("should not match an unrelated control")
	}
	if policyMatchesControl(policy, nil) {
		t.Error("empty wanted set should not match")
	}
}

// resolveException returns the first non-expired entry in a policy's own
// exception list (entries are already scoped to one policy by the map key
// in PolicyConfig, so there is no cross-policy matching).
func TestResolveException_FirstNonExpired(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	exceptions := []spec.PolicyException{
		{State: "waived", Reason: "expired waiver", ExpiresAt: "2026-01-01"},
		{State: "na", Reason: "live waiver"},
	}
	e := resolveException(exceptions, now)
	if e == nil {
		t.Fatal("expected the live (non-expired) exception")
	}
	if e.Reason != "live waiver" {
		t.Errorf("resolved reason = %q; want the live one (expired entries are skipped)", e.Reason)
	}
}

// An empty exception list yields no exception.
func TestResolveException_Empty(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	if e := resolveException(nil, now); e != nil {
		t.Errorf("empty list should yield nil; got %+v", e)
	}
}

// A control marked not_applicable cascades a whole-policy na to every
// policy that maps to it — the control-level replacement for the old
// per-policy wildcard.
func TestResolveControlException_NotApplicableCascades(t *testing.T) {
	policy := &core.Policy{
		ID:       "soc2.cc6.4.physical_access",
		Controls: []core.ControlRef{{ControlID: "CC6.4"}},
	}
	controls := map[string]spec.ControlConfig{
		"CC6.4": {Applicability: "not_applicable", Reason: "inherited from AWS"},
	}
	e := resolveControlException(policy, controls)
	if e == nil {
		t.Fatal("expected a cascaded na exception for a not_applicable control")
	}
	if e.State != core.StatusNA {
		t.Errorf("State = %q; want %q", e.State, core.StatusNA)
	}
	if e.Reason != "inherited from AWS" {
		t.Errorf("Reason = %q; want the control's reason", e.Reason)
	}
}

// A control that is applicable (or absent) cascades nothing.
func TestResolveControlException_NoMatch(t *testing.T) {
	policy := &core.Policy{
		ID:       "soc2.cc6.1.mfa",
		Controls: []core.ControlRef{{ControlID: "CC6.1"}},
	}
	controls := map[string]spec.ControlConfig{
		"CC6.4": {Applicability: "not_applicable", Reason: "inherited"},
	}
	if e := resolveControlException(policy, controls); e != nil {
		t.Errorf("a policy not under the excluded control should get nil; got %+v", e)
	}
	if e := resolveControlException(policy, nil); e != nil {
		t.Errorf("no controls config should yield nil; got %+v", e)
	}
}

// A second instance doubles the candidates for every slot it can fill.
// Shipped frameworks only use one-or-more, so both instances bind and
// their records union — but a project-local policy with exactly-one now
// has an ambiguity the operator must resolve explicitly.
func TestAutoBind_SecondInstanceAffectsCardinality(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "directory_user")
	registerSource(t, set, "aws.iam[backup]", "directory_user")
	configured := map[string]map[string]any{"aws.iam": {}, "aws.iam[backup]": {}}

	t.Run("one-or-more unions both instances", func(t *testing.T) {
		slot := &core.Slot{Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true}
		got, err := autoBindSlot("p1", "users", slot, set.Sources, configured)
		if err != nil {
			t.Fatalf("autoBindSlot: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("bindings = %+v; want both instances", got)
		}
		// Sorted by source ID, and each binding keeps its own instance
		// identity so the collector writes two distinct envelopes.
		if got[0].SourceID != "aws.iam" || got[1].SourceID != "aws.iam[backup]" {
			t.Errorf("bindings = %+v; want distinct instance IDs", got)
		}
	})

	t.Run("exactly-one now needs an explicit binding", func(t *testing.T) {
		slot := &core.Slot{Accepts: []string{"directory_user"}, Cardinality: core.SlotExactlyOne, Required: true}
		_, err := autoBindSlot("p1", "users", slot, set.Sources, configured)
		if err == nil {
			t.Fatal("want an error: two instances make a single-source slot ambiguous")
		}
	})
}
