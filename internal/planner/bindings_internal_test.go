package planner

import (
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// lookupSourcePlugin tolerates an "[instance]" suffix on the key by
// falling back to the base ID.
func TestLookupSourcePlugin_InstanceSuffixFallback(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "directory_user")

	if p := lookupSourcePlugin(set.Sources, "aws.iam"); p == nil {
		t.Fatal("exact key lookup failed")
	}
	if p := lookupSourcePlugin(set.Sources, "aws.iam[prod]"); p == nil {
		t.Error("instance-suffixed key should fall back to base ID")
	}
	if p := lookupSourcePlugin(set.Sources, "no.such.source"); p != nil {
		t.Error("unknown source should return nil")
	}
	if p := lookupSourcePlugin(set.Sources, "no.such[inst]"); p != nil {
		t.Error("unknown base of instance-suffixed key should return nil")
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

// resolveException matches a policy by exact ID and by trailing-wildcard
// prefix, and skips a non-matching exception (covers the wildcard branch
// of exceptionMatchesPolicy).
func TestResolveException_WildcardPrefixMatch(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	exceptions := []spec.ExceptionConfig{
		{Policy: "soc2.cc9.*", State: "waived", Reason: "family waiver"},
	}
	// Wildcard prefix matches.
	if e := resolveException("soc2.cc9.1.foo", exceptions, now); e == nil {
		t.Error("wildcard prefix should match soc2.cc9.1.foo")
	}
	// A policy outside the prefix does not match.
	if e := resolveException("soc2.cc6.1.mfa", exceptions, now); e != nil {
		t.Errorf("non-matching policy should not get an exception; got %+v", e)
	}
}

// An exact-ID exception matches only that policy.
func TestResolveException_ExactMatch(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	exceptions := []spec.ExceptionConfig{
		{Policy: "soc2.cc6.1.mfa", State: "na", Reason: "n/a"},
	}
	if e := resolveException("soc2.cc6.1.mfa", exceptions, now); e == nil {
		t.Error("exact ID should match")
	}
	if e := resolveException("soc2.cc6.1.other", exceptions, now); e != nil {
		t.Error("a different exact ID should not match")
	}
}
