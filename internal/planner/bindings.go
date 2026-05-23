package planner

import (
	"fmt"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// resolveBindings turns the project config's binding entries into
// fully-validated Binding values. The planner verifies that every
// referenced source plugin exists in the SourceRegistry and that its
// emits list includes the slot's declared evidence type. It also
// enforces the slot's cardinality (exactly-one, one-or-more, etc.).
func resolveBindings(policy *core.Policy, projectBindings map[string][]spec.BindingEntry, sources *registry.Registry[core.SourcePlugin]) (map[string][]Binding, error) {
	out := make(map[string][]Binding, len(policy.Slots))
	for slotName, slot := range policy.Slots {
		entries := projectBindings[slotName]
		bindings, err := resolveSlot(policy.ID, slotName, &slot, entries, sources)
		if err != nil {
			return nil, err
		}
		out[slotName] = bindings
	}
	// Project-config bindings for slots the policy does not declare
	// are a configuration error.
	for slotName := range projectBindings {
		if _, declared := policy.Slots[slotName]; !declared {
			return nil, fmt.Errorf("planner: policy %q: binding for unknown slot %q", policy.ID, slotName)
		}
	}
	return out, nil
}

func resolveSlot(policyID, slotName string, slot *core.Slot, entries []spec.BindingEntry, sources *registry.Registry[core.SourcePlugin]) ([]Binding, error) {
	bindings := make([]Binding, 0, len(entries))
	for i, e := range entries {
		sourceID, catalogID := parseBindingSource(e.Source)
		plugin, ok := sources.Lookup(sourceID)
		if !ok {
			return nil, fmt.Errorf("planner: policy %q slot %q binding[%d]: unknown source %q", policyID, slotName, i, sourceID)
		}
		if !sourceEmitsType(plugin, slot.Type) {
			return nil, fmt.Errorf("planner: policy %q slot %q binding[%d]: source %q does not emit evidence type %q (emits %v)", policyID, slotName, i, sourceID, slot.Type, plugin.Emits())
		}
		bindings = append(bindings, Binding{
			SourceID:   sourceID,
			CatalogID:  catalogID,
			SlotParams: e.SlotParams,
		})
	}
	if err := enforceCardinality(policyID, slotName, slot, len(bindings)); err != nil {
		return nil, err
	}
	return bindings, nil
}

func parseBindingSource(s string) (sourceID, catalogID string) {
	if idx := strings.Index(s, ":"); idx >= 0 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}

func sourceEmitsType(plugin core.SourcePlugin, evidenceType string) bool {
	for _, e := range plugin.Emits() {
		if e == evidenceType {
			return true
		}
	}
	return false
}

func enforceCardinality(policyID, slotName string, slot *core.Slot, n int) error {
	switch slot.Cardinality {
	case core.SlotExactlyOne:
		if n != 1 {
			return fmt.Errorf("planner: policy %q slot %q: cardinality exactly-one requires 1 binding, got %d", policyID, slotName, n)
		}
	case core.SlotAtMostOne:
		if n > 1 {
			return fmt.Errorf("planner: policy %q slot %q: cardinality at-most-one requires 0 or 1 binding, got %d", policyID, slotName, n)
		}
	case core.SlotOneOrMore:
		if n == 0 && slot.Required {
			return fmt.Errorf("planner: policy %q slot %q: cardinality one-or-more with required=true demands ≥1 binding, got 0", policyID, slotName)
		}
	case core.SlotOptional:
		// No constraint.
	default:
		return fmt.Errorf("planner: policy %q slot %q: unknown cardinality %q", policyID, slotName, slot.Cardinality)
	}
	return nil
}
