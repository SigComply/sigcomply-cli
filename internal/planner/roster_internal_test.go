package planner

import (
	"reflect"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Roster-role slots resolve first whatever their names sort to, so a
// subject slot named before the roster slot still sees its exclusions.
func TestOrderedSlotNames_RosterFirst(t *testing.T) {
	slots := map[string]core.Slot{
		"a_accounts": {Role: core.SlotRoleRosterSubject},
		"b_plain":    {},
		"z_roster":   {Role: core.SlotRoleRoster},
	}
	if got, want := orderedSlotNames(slots), []string{"z_roster", "a_accounts", "b_plain"}; !reflect.DeepEqual(got, want) {
		t.Errorf("orderedSlotNames = %v; want %v", got, want)
	}
}

// The roster source is excluded before the single-source ambiguity check:
// an exactly-one accounts slot with {okta (roster), github} is not
// ambiguous — okta was never a candidate.
func TestResolveBindingsWithRoster_ExclusionPrecedesAmbiguity(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, srcOkta, evDirectoryUser, "roster_entry")
	registerSource(t, set, srcGitHub, evDirectoryUser)
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			slotAccounts: {Accepts: []string{evDirectoryUser}, Cardinality: core.SlotExactlyOne, Required: true, Role: core.SlotRoleRosterSubject},
			slotRoster:   {Accepts: []string{"roster_entry"}, Cardinality: core.SlotExactlyOne, Required: true, Role: core.SlotRoleRoster},
		},
	}
	configured := map[string]map[string]any{srcOkta: {}, srcGitHub: {}}
	bindings, err := resolveBindingsWithRoster(policy, map[string][]spec.BindingEntry{}, set.Sources, configured, srcOkta)
	if err != nil {
		t.Fatalf("resolveBindingsWithRoster: %v", err)
	}
	if len(bindings[slotAccounts]) != 1 || bindings[slotAccounts][0].SourceID != srcGitHub {
		t.Errorf("accounts = %v; want [github]", bindings[slotAccounts])
	}
}

// An optional roster slot left unbound does not take the policy's other
// bindings down with it.
func TestDropBindingsIfRosterUnbound_OnlyRequiredRoster(t *testing.T) {
	policy := &core.Policy{Slots: map[string]core.Slot{
		slotRoster:   {Role: core.SlotRoleRoster, Required: false},
		slotAccounts: {Role: core.SlotRoleRosterSubject, Required: true},
	}}
	bindings := map[string][]Binding{slotRoster: nil, slotAccounts: {{SourceID: srcGitHub}}}
	dropBindingsIfRosterUnbound(policy, bindings)
	if len(bindings[slotAccounts]) != 1 {
		t.Errorf("accounts = %v; want kept (roster slot is optional)", bindings[slotAccounts])
	}
}
