package planner

import (
	"fmt"
	"sort"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// loadRoster reads experimental.roster and cross-checks it against the
// project's sources and the framework's policies. Every failure is a
// plan error (exit 3): a roster the operator named but the CLI cannot
// use would otherwise silently skip every roster-matching control.
// Returns (nil, nil) when no roster is designated.
func loadRoster(cfg *spec.ProjectConfig, framework core.Framework, set *registry.Set) (*spec.RosterConfig, error) {
	rc, err := spec.LoadRosterConfig(cfg)
	if err != nil || rc == nil {
		return nil, err
	}

	if _, configured := cfg.Sources[rc.Source]; !configured {
		return nil, fmt.Errorf("project config: experimental.roster.source: source %q is not configured in the sources: block", rc.Source)
	}
	plugin, ok := set.Sources.Lookup(rc.Source)
	if !ok {
		return nil, fmt.Errorf("project config: experimental.roster.source: unknown source %q", rc.Source)
	}
	// The emits check is generic — against whatever the framework's
	// roster slots accept — so a new roster evidence type needs no change
	// here. With no roster slot there is nothing to check against; that
	// case is a warning (RosterWarnings), not an error.
	if accepts := rosterSlotAccepts(cfg, framework, set); len(accepts) > 0 {
		if len(intersect(accepts, plugin.Emits())) == 0 {
			return nil, fmt.Errorf("project config: experimental.roster.source: source %q emits %v, none of which a roster slot accepts (roster slots accept %v)",
				rc.Source, plugin.Emits(), accepts)
		}
	}

	if err := checkRosterSourceKeys("aliases", keysOf(rc.Aliases), cfg); err != nil {
		return nil, err
	}
	if err := checkRosterSourceKeys("non_human", keysOf(rc.NonHuman), cfg); err != nil {
		return nil, err
	}
	return rc, nil
}

// checkRosterSourceKeys requires every source ID keying an aliases or
// non_human map to be a configured source: an entry for a source the
// project never collects from can never match an account, so it is a
// typo, not a declaration.
func checkRosterSourceKeys(field string, ids []string, cfg *spec.ProjectConfig) error {
	for _, id := range ids {
		if _, configured := cfg.Sources[id]; !configured {
			return fmt.Errorf("project config: experimental.roster.%s[%q]: source %q is not configured in the sources: block", field, id, id)
		}
	}
	return nil
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rosterSlotAccepts returns the sorted union of evidence types accepted
// by roster-role slots across the framework's policies and the project's
// local policies. Empty when no policy declares a roster slot.
func rosterSlotAccepts(cfg *spec.ProjectConfig, framework core.Framework, set *registry.Set) []string {
	seen := map[string]struct{}{}
	policies := frameworkPolicies(cfg, framework, set)
	for i := range policies {
		policy := &policies[i]
		for name := range policy.Slots {
			slot := policy.Slots[name]
			if slot.Role != core.SlotRoleRoster {
				continue
			}
			for _, t := range slot.Accepts {
				seen[t] = struct{}{}
			}
		}
	}
	return keysOf(seen)
}

// frameworkPolicies resolves every policy the project plans from — the
// framework's own plus project-local ones — ignoring unknown references
// (planPolicies reports those).
func frameworkPolicies(cfg *spec.ProjectConfig, framework core.Framework, set *registry.Set) []core.Policy {
	refs := framework.Policies()
	if cfg != nil {
		refs = append(refs, cfg.ProjectLocalPolicies...)
	}
	out := make([]core.Policy, 0, len(refs))
	for _, ref := range refs {
		if p, ok := set.Policies.Lookup(ref.PolicyID); ok {
			out = append(out, p)
		}
	}
	return out
}

// RosterWarnings returns the non-fatal findings about experimental.roster
// for the orchestrator to log: unrecognized subkeys (tolerated, per the
// experimental: hatch) and a roster designated for a framework none of
// whose policies has a roster slot. Returns nil when the block is absent
// or malformed (Plan reports the latter as an error).
func RosterWarnings(cfg *spec.ProjectConfig, set *registry.Set) []string {
	rc, err := spec.LoadRosterConfig(cfg)
	if err != nil || rc == nil {
		return nil
	}
	var out []string
	for _, k := range rc.UnknownKeys {
		out = append(out, fmt.Sprintf("ignoring unrecognized key experimental.roster.%s", k))
	}
	if set == nil {
		return out
	}
	framework, ok := set.Frameworks.Lookup(cfg.Framework)
	if ok && len(rosterSlotAccepts(cfg, framework, set)) == 0 {
		out = append(out, fmt.Sprintf("experimental.roster.source is set to %q but no policy in framework %q has a roster slot; the roster is not used",
			rc.Source, framework.ID()))
	}
	return out
}

// hasRosterRoleSlot reports whether any of the policy's slots takes part
// in roster matching.
func hasRosterRoleSlot(policy *core.Policy) bool {
	for name := range policy.Slots {
		if policy.Slots[name].Role != core.SlotRoleNone {
			return true
		}
	}
	return false
}

// rosterLinkFor builds the evaluator's view of the roster declaration for
// a policy with a roster-role slot; nil for every other policy. A policy
// with a roster slot but no experimental.roster block (bound through
// per-policy bindings, or unbound and about to skip) gets an empty link.
func rosterLinkFor(policy *core.Policy, rc *spec.RosterConfig) *RosterLink {
	if !hasRosterRoleSlot(policy) {
		return nil
	}
	if rc == nil {
		return &RosterLink{}
	}
	return &RosterLink{Source: rc.Source, Aliases: rc.Aliases, NonHuman: rc.NonHuman}
}

// dropBindingsIfRosterUnbound clears every binding of a policy whose
// required roster slot bound nothing. Such a policy is skipped at
// evaluation regardless, so collecting (and signing) evidence for its
// other slots would be wasted API calls and vault writes for records
// nothing reads.
func dropBindingsIfRosterUnbound(policy *core.Policy, bindings map[string][]Binding) {
	unbound := false
	for name := range policy.Slots {
		slot := policy.Slots[name]
		if slot.Role == core.SlotRoleRoster && slot.Required && len(bindings[name]) == 0 {
			unbound = true
			break
		}
	}
	if !unbound {
		return
	}
	for name := range bindings {
		bindings[name] = nil
	}
}
