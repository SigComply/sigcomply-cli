package planner

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// resolveBindings turns the project config into fully-validated Binding
// values for every slot the policy declares.
//
// Binding resolution is auto-by-default (Invariant #4 substitutability):
//   - If the project config names sources for a slot (an explicit
//     bindings: entry), the planner uses exactly those — the operator is
//     narrowing the slot to a chosen subset.
//   - Otherwise the planner auto-binds every CONFIGURED source whose
//     Emits() intersects the slot's accepts:. Configuring a source under
//     sources: is enough to make every policy that can consume it "just
//     work" — no per-policy YAML required.
//
// In both cases the planner verifies the referenced plugin exists and
// that its emits list includes the slot's declared evidence type, and it
// enforces the slot's cardinality. configuredSources is the set of source
// IDs the project actually declared under sources: (cfg.Sources); only
// those are candidates for auto-binding (the registry may hold more — the
// blank-imported builtins — but a source the operator never configured
// has no credentials and must not be bound).
func resolveBindings(policy *core.Policy, projectBindings map[string][]spec.BindingEntry, sources *registry.Registry[core.SourcePlugin], configuredSources map[string]map[string]any) (map[string][]Binding, error) {
	out := make(map[string][]Binding, len(policy.Slots))
	for slotName, slot := range policy.Slots {
		entries := projectBindings[slotName]
		bindings, err := resolveSlot(policy.ID, slotName, &slot, entries, sources, configuredSources)
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

func resolveSlot(policyID, slotName string, slot *core.Slot, entries []spec.BindingEntry, sources *registry.Registry[core.SourcePlugin], configuredSources map[string]map[string]any) ([]Binding, error) {
	if len(slot.Accepts) == 0 {
		return nil, fmt.Errorf("planner: policy %q slot %q: slot.Accepts is empty (must list at least one evidence type)", policyID, slotName)
	}
	if len(entries) > 0 {
		return resolveExplicitSlot(policyID, slotName, slot, entries, sources)
	}
	return autoBindSlot(policyID, slotName, slot, sources, configuredSources)
}

// resolveExplicitSlot resolves the operator-named sources for a slot. An
// explicit binding is an override: the planner uses exactly these sources
// and does not auto-bind. A named source that doesn't exist, or that
// emits nothing the slot accepts, is a hard plan error — the operator
// asked for it by name, so silence would hide a mistake.
func resolveExplicitSlot(policyID, slotName string, slot *core.Slot, entries []spec.BindingEntry, sources *registry.Registry[core.SourcePlugin]) ([]Binding, error) {
	bindings := make([]Binding, 0, len(entries))
	for i, e := range entries {
		sourceID, catalogID := parseBindingSource(e.Source)
		plugin, ok := sources.Lookup(sourceID)
		if !ok {
			return nil, fmt.Errorf("planner: policy %q slot %q binding[%d]: unknown source %q", policyID, slotName, i, sourceID)
		}
		accepted := intersect(slot.Accepts, plugin.Emits())
		if len(accepted) == 0 {
			hint := ""
			if siblings := siblingVersions(slot.Accepts, plugin.Emits()); len(siblings) > 0 {
				hint = fmt.Sprintf(" (version skew: source emits %v, a different version of an accepted type — extend the slot's accepts: or bind a source that emits one of %v)", siblings, slot.Accepts)
			}
			return nil, fmt.Errorf("planner: policy %q slot %q binding[%d]: source %q emits %v, none of which is in slot Accepts %v%s",
				policyID, slotName, i, sourceID, plugin.Emits(), slot.Accepts, hint)
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

// autoBindSlot binds every configured source whose Emits() intersects the
// slot's accepts:. This is the substitutability promise made concrete: a
// project that configures aws.iam gets every directory_user policy bound
// to it without writing a bindings: block. Sources are considered in
// sorted order for deterministic plans. A source that emits nothing the
// slot accepts is simply not bound (no error — unlike the explicit path,
// the operator never named it).
//
// Zero auto-binds on a required slot is permitted: the policy plans
// cleanly and is skipped at evaluation (surfaced loudly in the run
// summary so the operator sees the uncovered control). For single-source
// slots (exactly-one / at-most-one) more than one candidate is genuinely
// ambiguous — the planner refuses to guess and asks for an explicit
// binding rather than picking arbitrarily.
func autoBindSlot(policyID, slotName string, slot *core.Slot, sources *registry.Registry[core.SourcePlugin], configuredSources map[string]map[string]any) ([]Binding, error) {
	srcIDs := make([]string, 0, len(configuredSources))
	for id := range configuredSources {
		srcIDs = append(srcIDs, id)
	}
	sort.Strings(srcIDs)

	bindings := make([]Binding, 0, len(srcIDs))
	for _, srcID := range srcIDs {
		plugin := lookupSourcePlugin(sources, srcID)
		if plugin == nil {
			continue
		}
		accepted := intersect(slot.Accepts, plugin.Emits())
		if len(accepted) == 0 {
			continue
		}
		bindings = append(bindings, Binding{
			SourceID:      srcID,
			AcceptedTypes: accepted,
		})
	}

	switch slot.Cardinality {
	case core.SlotExactlyOne, core.SlotAtMostOne:
		if len(bindings) > 1 {
			ids := make([]string, len(bindings))
			for i := range bindings {
				ids[i] = bindings[i].SourceID
			}
			return nil, fmt.Errorf("planner: policy %q slot %q: cardinality %q accepts a single source but %d configured sources emit an accepted type (%v); add an explicit binding under bindings: to choose one",
				policyID, slotName, slot.Cardinality, len(bindings), ids)
		}
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

// evidenceTypeFamily returns the version-agnostic family of an evidence
// type ID by stripping a trailing ".v<N>" segment. "directory_user" and
// "directory_user.v2" both belong to the family "directory_user". IDs
// without a recognized version suffix are their own family.
func evidenceTypeFamily(typeID string) string {
	i := strings.LastIndex(typeID, ".")
	if i < 0 || i == len(typeID)-1 {
		return typeID
	}
	suffix := typeID[i+1:]
	if suffix[0] != 'v' || len(suffix) < 2 {
		return typeID
	}
	for _, r := range suffix[1:] {
		if r < '0' || r > '9' {
			return typeID
		}
	}
	return typeID[:i]
}

// siblingVersions returns the entries of emits that share a family with
// some entry in accepts but are not themselves accepted exactly. An
// exact match anywhere means there is no skew, so the result is empty.
func siblingVersions(accepts, emits []string) []string {
	acceptSet := make(map[string]struct{}, len(accepts))
	acceptFamilies := make(map[string]struct{}, len(accepts))
	for _, a := range accepts {
		acceptSet[a] = struct{}{}
		acceptFamilies[evidenceTypeFamily(a)] = struct{}{}
	}
	var siblings []string
	for _, e := range emits {
		if _, exact := acceptSet[e]; exact {
			return nil
		}
		if _, fam := acceptFamilies[evidenceTypeFamily(e)]; fam {
			siblings = append(siblings, e)
		}
	}
	return siblings
}

// detectCoverageGaps finds version-skew coverage gaps for a policy: each
// required slot with zero resolved bindings, paired with every
// configured source that emits a sibling version (same family, different
// ID, no exact match) of a type the slot accepts. Without surfacing
// these, the policy is silently skipped at evaluation and excluded from
// the compliance score. See CoverageGap. Results are sorted (by slot,
// then source) for deterministic output.
func detectCoverageGaps(policy *core.Policy, bindings map[string][]Binding, configuredSources map[string]map[string]any, sources *registry.Registry[core.SourcePlugin]) []CoverageGap {
	if len(configuredSources) == 0 {
		return nil
	}
	srcIDs := make([]string, 0, len(configuredSources))
	for id := range configuredSources {
		srcIDs = append(srcIDs, id)
	}
	sort.Strings(srcIDs)

	slotNames := make([]string, 0, len(policy.Slots))
	for name := range policy.Slots {
		slotNames = append(slotNames, name)
	}
	sort.Strings(slotNames)

	var gaps []CoverageGap
	for _, slotName := range slotNames {
		slot := policy.Slots[slotName]
		if !slot.Required || len(bindings[slotName]) > 0 {
			continue
		}
		// If any configured source emits an exactly-accepted type, the
		// slot is coverable — the skew near-miss is not the blocker, so
		// stay quiet for the whole slot. (An unbound-but-coverable slot is
		// a separate concern, not version skew.)
		if slotHasExactEmitter(slot.Accepts, srcIDs, sources) {
			continue
		}
		for _, srcID := range srcIDs {
			plugin := lookupSourcePlugin(sources, srcID)
			if plugin == nil {
				continue
			}
			siblings := siblingVersions(slot.Accepts, plugin.Emits())
			if len(siblings) == 0 {
				continue
			}
			gaps = append(gaps, CoverageGap{
				Slot:        slotName,
				Accepts:     slot.Accepts,
				Source:      srcID,
				SourceEmits: siblings,
			})
		}
	}
	return gaps
}

// slotHasExactEmitter reports whether any configured source emits a type
// the slot accepts exactly (not merely a sibling version).
func slotHasExactEmitter(accepts, srcIDs []string, sources *registry.Registry[core.SourcePlugin]) bool {
	acceptSet := make(map[string]struct{}, len(accepts))
	for _, a := range accepts {
		acceptSet[a] = struct{}{}
	}
	for _, srcID := range srcIDs {
		plugin := lookupSourcePlugin(sources, srcID)
		if plugin == nil {
			continue
		}
		for _, e := range plugin.Emits() {
			if _, ok := acceptSet[e]; ok {
				return true
			}
		}
	}
	return false
}

// lookupSourcePlugin resolves a configured-source key to its plugin,
// tolerating a "[instance]" suffix on the key by falling back to the
// base ID. Returns nil when no plugin is registered (the condition is
// surfaced elsewhere; here we simply skip it).
func lookupSourcePlugin(sources *registry.Registry[core.SourcePlugin], key string) core.SourcePlugin {
	if p, ok := sources.Lookup(key); ok {
		return p
	}
	if i := strings.IndexByte(key, '['); i > 0 {
		if p, ok := sources.Lookup(key[:i]); ok {
			return p
		}
	}
	return nil
}

func enforceCardinality(policyID, slotName string, slot *core.Slot, n int) error {
	// Zero bindings is always permitted, even for required slots: a
	// framework ships policies whose source plugins may not be configured
	// in a given project (the deferred-source model). An unbound required
	// slot plans cleanly here and is skipped at evaluation time
	// (requiredSlotsPopulated → status=skip), rather than aborting the
	// whole run with a plan error. A source that IS bound but emits no
	// accepting type is still a hard error — that check lives in
	// resolveSlot's per-entry intersection, not here.
	switch slot.Cardinality {
	case core.SlotExactlyOne, core.SlotAtMostOne:
		if n > 1 {
			return fmt.Errorf("planner: policy %q slot %q: cardinality %q allows at most 1 binding, got %d", policyID, slotName, slot.Cardinality, n)
		}
	case core.SlotOneOrMore, core.SlotOptional:
		// No upper bound; zero is allowed (skipped at evaluation).
	default:
		return fmt.Errorf("planner: policy %q slot %q: unknown cardinality %q", policyID, slotName, slot.Cardinality)
	}
	return nil
}
