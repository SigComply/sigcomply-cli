package planner

import (
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// validateProjectReferences catches the silent-no-op footgun: a key under
// policies: or controls: that does not name anything real (a typo'd policy
// ID, a control that no policy maps to) would otherwise be ignored — the
// project's override, parameter, cadence, or waiver would never apply and
// the operator would have no signal. Run once at plan start, after the
// framework is resolved, with a "did you mean …" suggestion so the fix is
// obvious. This is the "validate cross-references" step the registry's
// loading sequence anticipates.
//
// Source / slot / parameter references inside a binding are validated
// downstream by the binding resolver (unknown source, binding for unknown
// slot, undeclared parameter are already hard errors there); this pass
// covers the two reference kinds whose failure mode is silence.
func validateProjectReferences(cfg *spec.ProjectConfig, framework core.Framework, set *registry.Set) error {
	if cfg == nil {
		return nil
	}
	policyIDs, controlIDs := knownReferences(cfg, framework, set)

	for id := range cfg.Policies {
		if _, ok := policyIDs[id]; !ok {
			return fmt.Errorf("project config: policies[%q]: no such policy in framework %q%s",
				id, framework.ID(), didYouMean(id, policyIDs))
		}
	}
	for id := range cfg.Controls {
		if _, ok := controlIDs[id]; !ok {
			return fmt.Errorf("project config: controls[%q]: no such control in framework %q%s",
				id, framework.ID(), didYouMean(id, controlIDs))
		}
	}
	return nil
}

// knownReferences returns the set of valid policy IDs and control IDs for
// the active framework: every policy the framework ships plus any
// project-local policy, and the union of the controls those policies map
// to.
func knownReferences(cfg *spec.ProjectConfig, framework core.Framework, set *registry.Set) (policyIDs, controlIDs map[string]struct{}) {
	policyIDs = map[string]struct{}{}
	controlIDs = map[string]struct{}{}
	refs := framework.Policies()
	refs = append(refs, cfg.ProjectLocalPolicies...)
	for _, ref := range refs {
		policyIDs[ref.PolicyID] = struct{}{}
		policy, ok := set.Policies.Lookup(ref.PolicyID)
		if !ok {
			continue
		}
		for i := range policy.Controls {
			controlIDs[policy.Controls[i].ControlID] = struct{}{}
		}
	}
	return policyIDs, controlIDs
}

// didYouMean returns " (did you mean \"X\"?)" when some known ID is within
// a small edit distance of the typo'd one, else "". The threshold scales
// with the length so short IDs require a closer match.
func didYouMean(got string, known map[string]struct{}) string {
	best, bestDist := "", 1<<30
	for id := range known {
		if d := levenshtein(got, id); d < bestDist {
			best, bestDist = id, d
		}
	}
	maxDist := len(got)/3 + 1
	if best == "" || bestDist > maxDist {
		return ""
	}
	return fmt.Sprintf(" (did you mean %q?)", best)
}

// levenshtein computes the edit distance between a and b with the usual
// two-row dynamic-programming table. Small inputs (compliance IDs), so the
// allocation cost is negligible.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
