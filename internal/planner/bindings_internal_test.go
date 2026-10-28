package planner

import (
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Shared across the instance tests so goconst stays quiet.
const (
	srcAWSIAM       = "aws.iam"
	srcAWSIAMBackup = "aws.iam[backup]"
	srcGitHub       = "github"

	stateWaived = "waived"

	evDirectoryUser   = "directory_user"
	evDirectoryUserV2 = "directory_user.v2"

	slotUsers    = "users"
	slotRepos    = "repos"
	slotAccounts = "accounts"
	slotRoster   = "roster"

	ctrlCC64 = "CC6.4"
)

// lookupSourcePlugin is exact, including for instance keys. Every
// configured source is registered under its exact key, so a miss means
// the key names nothing real. A base-ID fallback would make a typo'd
// instance silently resolve to a different instance's plugin —
// collecting the wrong account and then labeling the evidence with the
// typo'd name.
func TestLookupSourcePlugin_IsExact(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, srcAWSIAM, evDirectoryUser)
	registerSource(t, set, srcAWSIAMBackup, evDirectoryUser)

	if p := lookupSourcePlugin(set.Sources, srcAWSIAM); p == nil {
		t.Fatal("exact key lookup failed")
	}
	if p := lookupSourcePlugin(set.Sources, srcAWSIAMBackup); p == nil {
		t.Error("a registered instance key must resolve")
	} else if p.ID() != srcAWSIAMBackup {
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

// resolveExceptions skips expired entries in a policy's own exception
// list (entries are already scoped to one policy by the map key in
// PolicyConfig, so there is no cross-policy matching).
func TestResolveExceptions_SkipsExpired(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	exceptions := []spec.PolicyException{
		{State: stateWaived, Reason: "expired waiver", ExpiresAt: "2026-01-01"},
		{State: "na", Reason: "live waiver"},
	}
	got := resolveExceptions(exceptions, now)
	if len(got) != 1 || got[0].Reason != "live waiver" {
		t.Fatalf("resolved = %+v; want only the live entry (expired entries are skipped)", got)
	}
}

// Every live scoped exception applies, each with its own scope: a
// second waiver for a second legacy resource must not be dropped.
func TestResolveExceptions_AllLiveScopedApply(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	exceptions := []spec.PolicyException{
		{State: stateWaived, Reason: "a", Scope: spec.ExceptionScope{ResourceID: "res-a"}},
		{State: stateWaived, Reason: "expired", ExpiresAt: "2026-03-01", Scope: spec.ExceptionScope{ResourceID: "res-x"}},
		{State: stateWaived, Reason: "b", Scope: spec.ExceptionScope{ResourcePattern: "legacy-*"}},
	}
	got := resolveExceptions(exceptions, now)
	if len(got) != 2 || got[0].Reason != "a" || got[1].ResourcePattern != "legacy-*" {
		t.Fatalf("resolved = %+v; want both live scoped entries in declared order", got)
	}
}

// A live whole-policy exception decides the result, so it is returned
// alone even when scoped entries are declared beside it.
func TestResolveExceptions_WholePolicyWins(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	exceptions := []spec.PolicyException{
		{State: stateWaived, Reason: "scoped", Scope: spec.ExceptionScope{ResourceID: "res-b"}},
		{State: "na", Reason: "whole"},
	}
	got := resolveExceptions(exceptions, now)
	if len(got) != 1 || got[0].Reason != "whole" {
		t.Fatalf("resolved = %+v; want only the whole-policy entry", got)
	}
}

// An empty exception list yields no exception.
func TestResolveExceptions_Empty(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	if got := resolveExceptions(nil, now); len(got) != 0 {
		t.Errorf("empty list should yield none; got %+v", got)
	}
}

// A control marked not_applicable cascades a whole-policy na to every
// policy that maps to it — the control-level replacement for the old
// per-policy wildcard.
func TestResolveControlException_NotApplicableCascades(t *testing.T) {
	policy := &core.Policy{
		ID:       "soc2.cc6.4.physical_access",
		Controls: []core.ControlRef{{ControlID: ctrlCC64}},
	}
	controls := map[string]spec.ControlConfig{
		ctrlCC64: {Applicability: applicabilityNotApplicable, Reason: "inherited from AWS"},
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
		ctrlCC64: {Applicability: applicabilityNotApplicable, Reason: "inherited"},
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
	registerSource(t, set, srcAWSIAM, evDirectoryUser)
	registerSource(t, set, srcAWSIAMBackup, evDirectoryUser)
	configured := map[string]map[string]any{srcAWSIAM: {}, srcAWSIAMBackup: {}}

	t.Run("one-or-more unions both instances", func(t *testing.T) {
		slot := &core.Slot{Accepts: []string{evDirectoryUser}, Cardinality: core.SlotOneOrMore, Required: true}
		got, err := autoBindSlot("p1", slotUsers, slot, set.Sources, configured, nil)
		if err != nil {
			t.Fatalf("autoBindSlot: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("bindings = %+v; want both instances", got)
		}
		// Sorted by source ID, and each binding keeps its own instance
		// identity so the collector writes two distinct envelopes.
		if got[0].SourceID != srcAWSIAM || got[1].SourceID != srcAWSIAMBackup {
			t.Errorf("bindings = %+v; want distinct instance IDs", got)
		}
	})

	t.Run("exactly-one now needs an explicit binding", func(t *testing.T) {
		slot := &core.Slot{Accepts: []string{evDirectoryUser}, Cardinality: core.SlotExactlyOne, Required: true}
		_, err := autoBindSlot("p1", slotUsers, slot, set.Sources, configured, nil)
		if err == nil {
			t.Fatal("want an error: two instances make a single-source slot ambiguous")
		}
	})
}

// A policy filed under two controls still backs the one in scope when the
// other is declared not applicable: excluding Confidentiality (C1.1) must
// not stop the public-bucket check that CC6.7 also relies on. Only when
// every mapped control is excluded does the policy become na.
func TestResolveControlException_MultiControlNeedsEveryControlExcluded(t *testing.T) {
	const cc67, c11 = "CC6.7", "C1.1"
	policy := &core.Policy{
		ID:       "soc2.cc6.7.storage_public_access_blocked",
		Controls: []core.ControlRef{{ControlID: cc67}, {ControlID: c11}},
	}
	oneOut := map[string]spec.ControlConfig{
		c11: {Applicability: applicabilityNotApplicable, Reason: "no confidentiality commitments"},
	}
	if e := resolveControlException(policy, oneOut); e != nil {
		t.Errorf("one of two controls excluded: got %+v; want nil (CC6.7 still needs the check)", e)
	}
	bothOut := map[string]spec.ControlConfig{
		c11:  {Applicability: applicabilityNotApplicable, Reason: "no confidentiality commitments"},
		cc67: {Applicability: applicabilityNotApplicable, Reason: "no data at rest"},
	}
	if e := resolveControlException(policy, bothOut); e == nil || e.State != core.StatusNA {
		t.Errorf("every control excluded: got %+v; want na", e)
	}
}
