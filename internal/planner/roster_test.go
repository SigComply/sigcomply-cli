package planner_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

const (
	rosterPolicyID   = "soc2.cc6.2.accounts_linked_to_roster"
	ordinaryPolicyID = "soc2.cc6.1.mfa_enforced"
	srcOktaID        = "okta"
	srcGitHubID      = "github"
	srcAWSIAMID      = "aws.iam"
	srcHRID          = "hr.system"
	slotRoster       = "roster"
	slotAccounts     = "accounts"
)

// rosterSet registers a synthetic roster-matching policy next to an
// ordinary one, plus fake sources: okta emits both a roster and accounts
// (the self-vouching case), github and aws.iam emit accounts only, and
// hr.system emits nothing a roster slot accepts.
func rosterSet(t *testing.T) *registry.Set {
	t.Helper()
	set := registry.NewSet()
	rosterPolicy := core.Policy{
		ID:       rosterPolicyID,
		Controls: []core.ControlRef{{ControlID: "CC6.2"}},
		Severity: core.SeverityHigh,
		Cadence:  cadenceDaily,
		Slots: map[string]core.Slot{
			slotRoster: {
				Accepts: []string{evRosterEntry}, Cardinality: core.SlotOneOrMore, // forced to exactly-one
				Required: true, Role: core.SlotRoleRoster,
			},
			slotAccounts: {
				Accepts: []string{evDirectoryUser}, Cardinality: core.SlotOneOrMore,
				Required: true, Role: core.SlotRoleRosterSubject,
			},
		},
	}
	ordinary := core.Policy{
		ID:       ordinaryPolicyID,
		Controls: []core.ControlRef{{ControlID: "CC6.1"}},
		Severity: core.SeverityHigh,
		Cadence:  cadenceDaily,
		Slots: map[string]core.Slot{
			slotUserDirectory: {Accepts: []string{evDirectoryUser}, Cardinality: core.SlotOneOrMore, Required: true},
		},
	}
	for _, p := range []*core.Policy{&rosterPolicy, &ordinary} {
		if err := set.Policies.Register(*p); err != nil {
			t.Fatalf("register policy: %v", err)
		}
	}
	fw := &fakeFramework{id: fwSOC2, version: "2017", policies: []core.PolicyRef{{PolicyID: rosterPolicyID}, {PolicyID: ordinaryPolicyID}}}
	if err := set.Frameworks.Register(fw); err != nil {
		t.Fatalf("register framework: %v", err)
	}
	for _, s := range []*fakeSource{
		{id: srcOktaID, emits: []string{evDirectoryUser, evRosterEntry}},
		{id: srcGitHubID, emits: []string{evDirectoryUser}},
		{id: srcAWSIAMID, emits: []string{evDirectoryUser}},
		{id: srcHRID, emits: []string{"hr_record"}},
	} {
		if err := set.Sources.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.id, err)
		}
	}
	return set
}

func rosterConfig(t *testing.T, body string) *spec.ProjectConfig {
	t.Helper()
	cfg, err := spec.LoadProjectConfig([]byte(`schema_version: project.v1
framework: soc2
sources:
  okta: {}
  github: {}
  aws.iam: {}
  hr.system: {}
` + body))
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	return &cfg
}

func planRoster(t *testing.T, set *registry.Set, cfg *spec.ProjectConfig) (*planner.RunPlan, error) {
	t.Helper()
	commit := commitFixture(t)
	return planner.Plan(&planner.Input{Config: cfg, Registries: set, CommitTime: commit, Now: commit})
}

func mustPlanRoster(t *testing.T, set *registry.Set, cfg *spec.ProjectConfig) *planner.RunPlan {
	t.Helper()
	plan, err := planRoster(t, set, cfg)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return plan
}

func plannedByID(t *testing.T, plan *planner.RunPlan, id string) *planner.PlannedPolicy {
	t.Helper()
	for i := range plan.Policies {
		if plan.Policies[i].Spec.ID == id {
			return &plan.Policies[i]
		}
	}
	t.Fatalf("policy %q not in plan", id)
	return nil
}

func boundIDs(bindings []planner.Binding) []string {
	out := make([]string, 0, len(bindings))
	for i := range bindings {
		out = append(out, bindings[i].SourceID)
	}
	return out
}

// Without a roster block the roster slot is never auto-bound — not even
// to okta, which emits roster_entry. The policy's other bindings are
// dropped so nothing is collected for a policy that will skip, and only
// the roster slot is recorded as unbound.
func TestPlanRoster_NoRosterBlockLeavesRosterSlotUnbound(t *testing.T) {
	set := rosterSet(t)
	plan := mustPlanRoster(t, set, rosterConfig(t, ""))
	pp := plannedByID(t, plan, rosterPolicyID)

	for slot, b := range pp.Bindings {
		if len(b) != 0 {
			t.Errorf("slot %q bindings = %v; want none (roster slot unbound drops every binding)", slot, boundIDs(b))
		}
	}
	if want := []string{slotRoster}; !reflect.DeepEqual(pp.UnboundRequiredSlots, want) {
		t.Errorf("UnboundRequiredSlots = %v; want %v", pp.UnboundRequiredSlots, want)
	}
	if pp.Roster == nil || pp.Roster.Source != "" {
		t.Errorf("Roster = %+v; want an empty non-nil link", pp.Roster)
	}
}

// Ordinary policies plan exactly as before, with or without a roster.
func TestPlanRoster_OrdinaryPolicyUnchanged(t *testing.T) {
	set := rosterSet(t)
	for _, body := range []string{"", "experimental:\n  roster:\n    source: okta\n"} {
		plan := mustPlanRoster(t, set, rosterConfig(t, body))
		pp := plannedByID(t, plan, ordinaryPolicyID)
		want := []string{srcAWSIAMID, srcGitHubID, srcOktaID}
		if got := boundIDs(pp.Bindings[slotUserDirectory]); !reflect.DeepEqual(got, want) {
			t.Errorf("roster %q: user_directory bound %v; want %v", body, got, want)
		}
		if pp.Roster != nil {
			t.Errorf("roster %q: ordinary policy Roster = %+v; want nil", body, pp.Roster)
		}
		if len(pp.UnboundRequiredSlots) != 0 {
			t.Errorf("roster %q: UnboundRequiredSlots = %v; want none", body, pp.UnboundRequiredSlots)
		}
	}
}

// With roster.source set, the roster slot binds to it, and the accounts
// slot auto-binds every other matching source — never the roster source.
func TestPlanRoster_DesignatedSourceBindsAndIsExcludedFromSubject(t *testing.T) {
	set := rosterSet(t)
	cfg := rosterConfig(t, `experimental:
  roster:
    source: okta
    aliases:
      github: { JDoe: jane@acme.com }
    non_human:
      aws.iam: [Terraform-Deployer]
`)
	plan := mustPlanRoster(t, set, cfg)
	pp := plannedByID(t, plan, rosterPolicyID)

	if got := boundIDs(pp.Bindings[slotRoster]); !reflect.DeepEqual(got, []string{srcOktaID}) {
		t.Errorf("roster bound %v; want [okta]", got)
	}
	if got := pp.Bindings[slotRoster][0].AcceptedTypes; !reflect.DeepEqual(got, []string{evRosterEntry}) {
		t.Errorf("roster AcceptedTypes = %v; want [roster_entry]", got)
	}
	if got := boundIDs(pp.Bindings[slotAccounts]); !reflect.DeepEqual(got, []string{srcAWSIAMID, srcGitHubID}) {
		t.Errorf("accounts bound %v; want [aws.iam github] (okta excluded)", got)
	}
	if len(pp.UnboundRequiredSlots) != 0 {
		t.Errorf("UnboundRequiredSlots = %v; want none", pp.UnboundRequiredSlots)
	}
	want := &planner.RosterLink{
		Source:   srcOktaID,
		Aliases:  map[string]map[string]string{srcGitHubID: {"jdoe": "jane@acme.com"}},
		NonHuman: map[string][]string{srcAWSIAMID: {"terraform-deployer"}},
	}
	if !reflect.DeepEqual(pp.Roster, want) {
		t.Errorf("Roster = %+v; want %+v", pp.Roster, want)
	}
}

// A per-policy explicit roster binding wins over the designation, and
// that source is the one excluded from the accounts slot.
func TestPlanRoster_ExplicitRosterBindingExcludedFromSubject(t *testing.T) {
	set := rosterSet(t)
	if err := set.Sources.Register(&fakeSource{id: "azure.entra", emits: []string{evDirectoryUser, evRosterEntry}}); err != nil {
		t.Fatal(err)
	}
	cfg := rosterConfig(t, `  azure.entra: {}
experimental:
  roster:
    source: okta
policies:
  soc2.cc6.2.accounts_linked_to_roster:
    bindings:
      roster: [azure.entra]
`)
	plan := mustPlanRoster(t, set, cfg)
	pp := plannedByID(t, plan, rosterPolicyID)
	if got := boundIDs(pp.Bindings[slotRoster]); !reflect.DeepEqual(got, []string{"azure.entra"}) {
		t.Errorf("roster bound %v; want [azure.entra]", got)
	}
	want := []string{srcAWSIAMID, srcGitHubID, srcOktaID}
	if got := boundIDs(pp.Bindings[slotAccounts]); !reflect.DeepEqual(got, want) {
		t.Errorf("accounts bound %v; want %v (azure.entra excluded, okta is just an account source here)", got, want)
	}
}

// Explicit per-policy roster binding with no roster block at all still
// binds, and gets an empty RosterLink.
func TestPlanRoster_ExplicitRosterBindingWithoutBlock(t *testing.T) {
	set := rosterSet(t)
	cfg := rosterConfig(t, `policies:
  soc2.cc6.2.accounts_linked_to_roster:
    bindings:
      roster: [okta]
`)
	pp := plannedByID(t, mustPlanRoster(t, set, cfg), rosterPolicyID)
	if got := boundIDs(pp.Bindings[slotAccounts]); !reflect.DeepEqual(got, []string{srcAWSIAMID, srcGitHubID}) {
		t.Errorf("accounts bound %v; want [aws.iam github]", got)
	}
	if pp.Roster == nil || pp.Roster.Source != "" || pp.Roster.Aliases != nil {
		t.Errorf("Roster = %+v; want empty link", pp.Roster)
	}
}

// Explicit accounts bindings are honored, minus nothing — unless they name
// the roster source.
func TestPlanRoster_ExplicitSubjectBinding(t *testing.T) {
	set := rosterSet(t)
	ok := rosterConfig(t, `experimental:
  roster:
    source: okta
policies:
  soc2.cc6.2.accounts_linked_to_roster:
    bindings:
      accounts: [github]
`)
	pp := plannedByID(t, mustPlanRoster(t, set, ok), rosterPolicyID)
	if got := boundIDs(pp.Bindings[slotAccounts]); !reflect.DeepEqual(got, []string{srcGitHubID}) {
		t.Errorf("accounts bound %v; want [github]", got)
	}

	bad := rosterConfig(t, `experimental:
  roster:
    source: okta
policies:
  soc2.cc6.2.accounts_linked_to_roster:
    bindings:
      accounts: [github, okta]
`)
	_, err := planRoster(t, set, bad)
	if err == nil {
		t.Fatal("want an error binding the roster source to the accounts slot; got nil")
	}
	for _, want := range []string{`slot "accounts" binding[1]`, `source "okta" is bound to the roster slot "roster"`, "cannot vouch for its own accounts"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v; want it to contain %q", err, want)
		}
	}
}

func TestPlanRoster_Rejects(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{
			name: "roster source not configured",
			body: "experimental:\n  roster:\n    source: azure.entra\n",
			want: `experimental.roster.source: source "azure.entra" is not configured in the sources: block`,
		},
		{
			name: "roster source emits nothing a roster slot accepts",
			body: "experimental:\n  roster:\n    source: github\n",
			want: `source "github" emits [directory_user], none of which a roster slot accepts (roster slots accept [roster_entry])`,
		},
		{
			name: "roster source configured but not registered",
			body: "  nope: {}\nexperimental:\n  roster:\n    source: nope\n",
			want: `experimental.roster.source: unknown source "nope"`,
		},
		{
			name: "aliases for an unconfigured source",
			body: "experimental:\n  roster:\n    source: okta\n    aliases: {gitlab: {jdoe: jane@acme.com}}\n",
			want: `experimental.roster.aliases["gitlab"]: source "gitlab" is not configured`,
		},
		{
			name: "non_human for an unconfigured source",
			body: "experimental:\n  roster:\n    source: okta\n    non_human: {gitlab: [bot]}\n",
			want: `experimental.roster.non_human["gitlab"]: source "gitlab" is not configured`,
		},
		{
			name: "bracketed roster source",
			body: "  okta[second]: {}\nexperimental:\n  roster:\n    source: okta[second]\n",
			want: "bracketed multi-instance",
		},
		{
			name: "empty alias",
			body: "experimental:\n  roster:\n    source: okta\n    aliases: {github: {jdoe: \"\"}}\n",
			want: "alias must be a non-empty roster email",
		},
		{
			name: "two explicit roster bindings",
			body: "policies:\n  soc2.cc6.2.accounts_linked_to_roster:\n    bindings:\n      roster: [okta, okta]\n",
			want: "allows at most 1 binding, got 2",
		},
	}
	set := rosterSet(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := planRoster(t, set, rosterConfig(t, c.body))
			if err == nil {
				t.Fatalf("want error containing %q; got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v; want it to contain %q", err, c.want)
			}
		})
	}
}

// Planning the same config repeatedly yields identical bindings (map
// iteration must not leak into slot resolution order).
func TestPlanRoster_Deterministic(t *testing.T) {
	set := rosterSet(t)
	cfg := rosterConfig(t, "experimental:\n  roster:\n    source: okta\n")
	first := plannedByID(t, mustPlanRoster(t, set, cfg), rosterPolicyID)
	for i := 0; i < 50; i++ {
		again := plannedByID(t, mustPlanRoster(t, set, cfg), rosterPolicyID)
		if !reflect.DeepEqual(first.Bindings, again.Bindings) {
			t.Fatalf("run %d bindings = %v; want %v", i, again.Bindings, first.Bindings)
		}
	}
}

func TestRosterWarnings(t *testing.T) {
	set := rosterSet(t)
	if w := planner.RosterWarnings(rosterConfig(t, ""), set); w != nil {
		t.Errorf("no roster block: warnings = %v; want none", w)
	}
	w := planner.RosterWarnings(rosterConfig(t, "experimental:\n  roster:\n    source: okta\n    alias: {}\n"), set)
	if want := []string{"ignoring unrecognized key experimental.roster.alias"}; !reflect.DeepEqual(w, want) {
		t.Errorf("warnings = %v; want %v", w, want)
	}

	// A framework with no roster slot: the roster is configured for nothing.
	plain := setUp(t)
	cfg := &spec.ProjectConfig{
		Framework:    fwSOC2,
		Sources:      map[string]map[string]any{srcOktaID: {}},
		Experimental: map[string]any{"roster": map[string]any{"source": srcOktaID}},
	}
	w = planner.RosterWarnings(cfg, plain)
	if len(w) != 1 || !strings.Contains(w[0], "no policy in framework \"soc2\" has a roster slot") {
		t.Errorf("warnings = %v; want the unused-roster warning", w)
	}
	// ...and it still plans (nothing to check emits against).
	cfg.Period = spec.PeriodConfig{FiscalCalendar: spec.FiscalCalendarConfig{Type: fiscalCalendarQuarter}}
	if _, err := planRoster(t, plain, cfg); err != nil {
		t.Errorf("Plan with an unused roster: %v", err)
	}
}
