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
	registerSource(t, set, srcOkta, "directory_user", "roster_entry")
	registerSource(t, set, "github", "directory_user")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"accounts": {Accepts: []string{"directory_user"}, Cardinality: core.SlotExactlyOne, Required: true, Role: core.SlotRoleRosterSubject},
			"roster":   {Accepts: []string{"roster_entry"}, Cardinality: core.SlotExactlyOne, Required: true, Role: core.SlotRoleRoster},
		},
	}
	configured := map[string]map[string]any{srcOkta: {}, "github": {}}
	bindings, err := resolveBindingsWithRoster(policy, map[string][]spec.BindingEntry{}, set.Sources, configured, srcOkta)
	if err != nil {
		t.Fatalf("resolveBindingsWithRoster: %v", err)
	}
	if len(bindings["accounts"]) != 1 || bindings["accounts"][0].SourceID != "github" {
		t.Errorf("accounts = %v; want [github]", bindings["accounts"])
	}
}

// An optional roster slot left unbound does not take the policy's other
// bindings down with it.
func TestDropBindingsIfRosterUnbound_OnlyRequiredRoster(t *testing.T) {
	policy := &core.Policy{Slots: map[string]core.Slot{
		"roster":   {Role: core.SlotRoleRoster, Required: false},
		"accounts": {Role: core.SlotRoleRosterSubject, Required: true},
	}}
	bindings := map[string][]Binding{"roster": nil, "accounts": {{SourceID: "github"}}}
	dropBindingsIfRosterUnbound(policy, bindings)
	if len(bindings["accounts"]) != 1 {
		t.Errorf("accounts = %v; want kept (roster slot is optional)", bindings["accounts"])
	}
}
