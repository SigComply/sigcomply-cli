package evaluator

import (
	"context"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// usageCtx builds an evalCtx wired to a fresh accumulator, the way
// evaluateOne does.
func usageCtx(roster *planner.RosterLink) (*evalCtx, *RosterUsage) {
	usage := NewRosterUsage()
	usage.Declare(roster)
	ec := newEvalCtx(nil, nil, roster)
	ec.usage = usage
	return ec, usage
}

func keyStrings(keys []RosterKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.SourceID+"/"+k.Name)
	}
	return out
}

func assertKeys(t *testing.T, label string, got []RosterKey, want ...string) {
	t.Helper()
	gotS := keyStrings(got)
	if len(gotS) != len(want) {
		t.Fatalf("%s = %v; want %v", label, gotS, want)
	}
	for i := range want {
		if gotS[i] != want[i] {
			t.Errorf("%s = %v; want %v", label, gotS, want)
			return
		}
	}
}

// An alias key naming a record's id, username or principal_id is used,
// so it is never reported.
func TestRosterUsage_AliasMatchedByEveryName(t *testing.T) {
	roster := &planner.RosterLink{
		Aliases: map[string]map[string]string{
			testSourceGitHub: {testNameJdoe: testEmailJane},
			testSourceAWSIAM: {testNameJaneDoe: testEmailJane},
			testSourceGCPIAM: {"user:jane@acme.com": testEmailJane},
		},
	}
	ec, usage := usageCtx(roster)

	byID := account(testSourceGitHub, "JDoe", nil)
	byUsername := account(testSourceAWSIAM, "AIDA1", map[string]any{fieldUsername: "Jane.Doe"})
	byPrincipal := binding("user:Jane@Acme.com", "user:Jane@Acme.com", principalTypeUser)
	for _, r := range []core.EvidenceRecord{byID, byUsername, byPrincipal} {
		ec.resolveAccount(&r)
	}

	assertKeys(t, "UnusedAliases", usage.UnusedAliases())
}

// An alias key no collected account carries is reported — that is the
// typo this warning exists for.
func TestRosterUsage_UnmatchedAliasIsReported(t *testing.T) {
	roster := &planner.RosterLink{
		Aliases: map[string]map[string]string{
			testSourceGitHub: {testNameJdoe: testEmailJane, "jdoee": testEmailJdoe},
		},
	}
	ec, usage := usageCtx(roster)
	r := account(testSourceGitHub, testNameJdoe, nil)
	ec.resolveAccount(&r)

	assertKeys(t, "UnusedAliases", usage.UnusedAliases(), testSourceGitHub+"/jdoee")
}

// The same name under a source that never produced it is still unused:
// keys are (source, name) pairs, not bare names.
func TestRosterUsage_AliasIsPerSource(t *testing.T) {
	roster := &planner.RosterLink{
		Aliases: map[string]map[string]string{
			testSourceGitHub: {testNameJdoe: testEmailJane},
			testSourceAWSIAM: {testNameJdoe: testEmailJane},
		},
	}
	ec, usage := usageCtx(roster)
	r := account(testSourceGitHub, testNameJdoe, nil)
	ec.resolveAccount(&r)

	assertKeys(t, "UnusedAliases", usage.UnusedAliases(), testSourceAWSIAM+"/jdoe")
}

// non_human has the identical hole and the identical accumulator.
func TestRosterUsage_NonHumanMatchedAndUnmatched(t *testing.T) {
	roster := &planner.RosterLink{
		NonHuman: map[string][]string{
			testSourceGitHub: {testNameCIBot, "acme-ci-bott"},
			testSourceAWSIAM: {testNameDeployer},
		},
	}
	ec, usage := usageCtx(roster)
	bot := account(testSourceGitHub, "Acme-CI-Bot", nil)
	deployer := account(testSourceAWSIAM, "AIDA2", map[string]any{fieldUsername: testNameDeployer})
	for _, r := range []core.EvidenceRecord{bot, deployer} {
		ec.resolveAccount(&r)
	}

	assertKeys(t, "UnusedNonHuman", usage.UnusedNonHuman(), testSourceGitHub+"/acme-ci-bott")
	assertKeys(t, "UnusedAliases", usage.UnusedAliases())
}

// A non_human entry for an account already non-human by construction
// (is_root, a non-user principal_type) is still used — the operator's
// declaration matched a real account, whatever else also marked it.
func TestRosterUsage_NonHumanKeyOnRootAccountIsUsed(t *testing.T) {
	roster := &planner.RosterLink{NonHuman: map[string][]string{testSourceAWSIAM: {"root"}}}
	ec, usage := usageCtx(roster)
	root := account(testSourceAWSIAM, "root", map[string]any{fieldIsRoot: true})
	link := ec.resolveAccount(&root)
	if !link.nonHuman {
		t.Error("root must stay non-human")
	}
	assertKeys(t, "UnusedNonHuman", usage.UnusedNonHuman())
}

// No roster: nothing is declared, nothing is reported, nothing panics.
func TestRosterUsage_NoRoster(t *testing.T) {
	ec, usage := usageCtx(nil)
	r := account(testSourceGitHub, testNameJdoe, map[string]any{linkedByEmail: testEmailJane})
	ec.resolveAccount(&r)
	assertKeys(t, "UnusedAliases", usage.UnusedAliases())
	assertKeys(t, "UnusedNonHuman", usage.UnusedNonHuman())

	// A nil accumulator is the pre-existing call shape (tests, rule:
	// policies) and must stay a no-op.
	plain := newEvalCtx(nil, nil, &planner.RosterLink{Aliases: map[string]map[string]string{testSourceGitHub: {testNameJdoe: testEmailJane}}})
	plain.resolveAccount(&r)
	var nilUsage *RosterUsage
	nilUsage.Declare(nil)
	if got := nilUsage.UnusedAliases(); got != nil {
		t.Errorf("nil usage UnusedAliases = %v; want nil", got)
	}
}

// rosterUsagePolicy is a minimal roster-shaped policy: one accounts
// slot, filtered on account.* so resolveAccount runs over every record
// before filtering — the shape the shipped roster policies have.
func rosterUsagePolicy(id string, roster *planner.RosterLink) planner.PlannedPolicy {
	return planner.PlannedPolicy{
		Spec: core.Policy{
			ID:           id,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				slotAccounts: {Accepts: []string{testTypeDirectoryUser}, Required: true},
			},
			PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot:        slotAccounts,
				Quantifier:  core.QuantifierAll,
				Filter:      &core.PassWhenCondition{Op: "eq", Field: fieldAccountNonHuman, Value: false},
				Condition:   &core.PassWhenCondition{Op: "eq", Field: fieldAccountActive, Value: true},
				IdentityKey: fieldAccountRef,
			}}},
		},
		Parameters:     map[string]any{},
		ShouldEvaluate: true,
		Roster:         roster,
	}
}

// The planner hands every roster policy the same maps but each policy
// gets its own evalCtx, so "unused" is only decidable as the union
// across the run: a key used by one roster policy is used, full stop.
func TestRosterUsage_UnionAcrossPolicies(t *testing.T) {
	roster := &planner.RosterLink{
		Aliases: map[string]map[string]string{
			testSourceGitHub: {testNameJdoe: testEmailJane},
			testSourceAWSIAM: {testNameJaneDoe: testEmailJane},
			"gone":           {"ghost": testEmailJdoe},
		},
		NonHuman: map[string][]string{
			testSourceGitHub: {testNameCIBot},
			"gone":           {"phantom"},
		},
	}
	// Two policies over the same roster maps, each binding a different
	// source — exactly what two roster policies with differently-bound
	// accounts slots look like.
	usage := NewRosterUsage()
	in := &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{
			rosterUsagePolicy("p.a", roster),
			rosterUsagePolicy("p.b", roster),
		}},
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p.a": {slotAccounts: {account(testSourceGitHub, testNameJdoe, nil), account(testSourceGitHub, testNameCIBot, nil)}},
			"p.b": {slotAccounts: {account(testSourceAWSIAM, testNameJaneDoe, nil)}},
		},
		RosterUsage: usage,
	}
	if _, err := Evaluate(context.Background(), in); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	assertKeys(t, "UnusedAliases", usage.UnusedAliases(), "gone/ghost")
	assertKeys(t, "UnusedNonHuman", usage.UnusedNonHuman(), "gone/phantom")
}

// A run that collected no account at all used no key, so every declared
// key is reported — including on the skip path, where the required
// accounts slot is empty and no rule runs.
func TestRosterUsage_ZeroAccountsReportsEveryKey(t *testing.T) {
	roster := &planner.RosterLink{
		Aliases:  map[string]map[string]string{testSourceGitHub: {testNameJdoe: testEmailJane, "bobby": testEmailJdoe}},
		NonHuman: map[string][]string{testSourceGitHub: {testNameCIBot}},
	}
	usage := NewRosterUsage()
	in := &Input{
		Plan:            &planner.RunPlan{Policies: []planner.PlannedPolicy{rosterUsagePolicy("p.a", roster)}},
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{"p.a": {slotAccounts: nil}},
		RosterUsage:     usage,
	}
	results, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Status != core.StatusSkip {
		t.Fatalf("status = %q; want skip", results[0].Status)
	}
	assertKeys(t, "UnusedAliases", usage.UnusedAliases(), testSourceGitHub+"/bobby", testSourceGitHub+"/jdoe")
	assertKeys(t, "UnusedNonHuman", usage.UnusedNonHuman(), testSourceGitHub+"/acme-ci-bot")
}

// A carried-forward policy never looks at an account, so it declares
// nothing: warning on a run that re-evaluated nothing would fire on
// every daily run of an annual-cadence roster policy.
func TestRosterUsage_CarriedForwardDeclaresNothing(t *testing.T) {
	roster := &planner.RosterLink{Aliases: map[string]map[string]string{testSourceGitHub: {testNameJdoe: testEmailJane}}}
	pp := rosterUsagePolicy("p.a", roster)
	pp.ShouldEvaluate = false
	usage := NewRosterUsage()
	if _, err := Evaluate(context.Background(), &Input{
		Plan:        &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		RosterUsage: usage,
	}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	assertKeys(t, "UnusedAliases", usage.UnusedAliases())
}
