package planner

import (
	"sort"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// unboundRequiredSlots returns the names of a policy's required slots
// that resolved to zero bindings, sorted for determinism.
//
// This is the plain "no configured source emits what this slot accepts"
// case, and it is deliberately distinct from detectCoverageGaps, which
// reports only the narrower *version-skew* near-miss (a configured source
// emits a sibling version of an accepted type). The two answer different
// questions and must not be merged: skew is a warning about a fixable
// mismatch, whereas an unbound required slot is the signal that a whole
// control has no evidence behind it.
//
// Such a policy plans cleanly (enforceCardinality permits zero bindings —
// the deferred-source model) and is skipped at evaluation, which drops it
// out of the compliance-score denominator entirely. Recording it here is
// what lets the scope report tell "this control was checked and passed"
// apart from "this control was never looked at".
//
// Returns nil when nothing is unbound, so the common case adds no
// allocation and serialises as an absent field.
func unboundRequiredSlots(policy *core.Policy, bindings map[string][]Binding) []string {
	var out []string
	for name, slot := range policy.Slots {
		if !slot.Required {
			continue
		}
		if len(bindings[name]) == 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
