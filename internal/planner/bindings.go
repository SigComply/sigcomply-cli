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
	if len(slot.Accepts) == 0 {
		return nil, fmt.Errorf("planner: policy %q slot %q: slot.Accepts is empty (must list at least one evidence type)", policyID, slotName)
	}
	bindings := make([]Binding, 0, len(entries))
	for i, e := range entries {
		sourceID, catalogID := parseBindingSource(e.Source)
		plugin, ok := sources.Lookup(sourceID)
		if !ok {
			return nil, fmt.Errorf("planner: policy %q slot %q binding[%d]: unknown source %q", policyID, slotName, i, sourceID)
		}
		accepted := intersect(slot.Accepts, plugin.Emits())
		if len(accepted) == 0 {
			return nil, fmt.Errorf("planner: policy %q slot %q binding[%d]: source %q emits %v, none of which is in slot Accepts %v",
				policyID, slotName, i, sourceID, plugin.Emits(), slot.Accepts)
		}
		bindings = append(bindings, Binding{
			SourceID:      sourceID,
			AcceptedTypes: accepted,
			CatalogID:     catalogID,
			SlotParams:    e.SlotParams,
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

// intersect returns the elements of accepts that also appear in emits,
// preserving accepts-order. Order is the policy author's priority
// statement: when a plugin emits multiple matching types, the slot's
// declared order is what callers (e.g. envelope-grouping in the
// collector) honor.
func intersect(accepts, emits []string) []string {
	emitSet := make(map[string]struct{}, len(emits))
	for _, e := range emits {
		emitSet[e] = struct{}{}
	}
	out := make([]string, 0, len(accepts))
	for _, a := range accepts {
		if _, ok := emitSet[a]; ok {
			out = append(out, a)
		}
	}
	return out
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
