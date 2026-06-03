package planner

import (
	"fmt"
	"sort"
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
