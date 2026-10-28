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
	if err := validatePolicyControls(cfg, framework, set); err != nil {
		return err
	}
	policyIDs, controlIDs := knownReferences(cfg, framework, set)

	for id := range cfg.Policies {
		if _, ok := policyIDs[id]; !ok {
			return fmt.Errorf("project config: policies[%q]: no such policy in framework %q%s",
				id, framework.ID(), didYouMean(id, policyIDs))
		}
		if err := checkAutomatedOverride(id, cfg.Policies[id].EvidenceMode, set); err != nil {
			return err
		}
	}
	for id := range cfg.Controls {
		if _, ok := controlIDs[id]; !ok {
			return fmt.Errorf("project config: controls[%q]: no such control in framework %q%s",
				id, framework.ID(), didYouMean(id, controlIDs))
		}
	}
	return validateApplicability(cfg, framework)
}

// validatePolicyControls checks the control a project-local policy maps
// to against the framework's control catalog.
//
// A typo there ("CC6.01" for "CC6.1") is silent otherwise: the policy
// still runs and still counts toward the score, but it joins no catalog
// control, so coverage and the Statement of Applicability report the real
// control as having no policy behind it.
//
// Shipped policies are held to the same rule by a test over every
// built-in framework (TestValidatePolicyControls_ShippedFrameworksPass),
// not here: a bad mapping in the binary is our bug, and failing the
// customer's run for it would leave them nothing to fix.
func validatePolicyControls(cfg *spec.ProjectConfig, framework core.Framework, set *registry.Set) error {
	catalog := map[string]struct{}{}
	for _, c := range framework.Controls() {
		catalog[c.ID] = struct{}{}
	}
	return checkPolicyControls(cfg.ProjectLocalPolicies, framework.ID(), catalog, set)
}

// checkPolicyControls reports the first policy in refs that maps to a
// control of frameworkID missing from catalog. A ref naming another
// framework is a cross-framework mapping this catalog cannot judge, so
// it is skipped; a ref naming none (a project-local policy's `control:`)
// belongs to the active framework.
func checkPolicyControls(refs []core.PolicyRef, frameworkID string, catalog map[string]struct{}, set *registry.Set) error {
	for _, ref := range refs {
		policy, ok := set.Policies.Lookup(ref.PolicyID)
		if !ok {
			continue
		}
		for _, cr := range policy.Controls {
			if cr.Framework != "" && cr.Framework != frameworkID {
				continue
			}
			if _, ok := catalog[cr.ControlID]; !ok {
				return fmt.Errorf("policy %q: control %q is not in the %s control catalog%s",
					policy.ID, cr.ControlID, frameworkID, didYouMean(cr.ControlID, catalog))
			}
		}
	}
	return nil
}

// validateApplicability rejects an applicability exclusion against a
// management-system requirement.
//
// Applicability is a Statement-of-Applicability concept and the SoA is
// about the control catalog: ISO/IEC 27001:2022 6.1.3 d asks which
// controls are necessary and why any were left out. Clauses 4-10 are
// not on that menu — certification is granted against the
// management system, so declining one is declining to have an ISMS. The
// cascade in resolveControlException would otherwise honor it
// silently, turning every policy under the clause into an N/A and
// lifting the compliance score for it, which is the most expensive way
// this could fail.
func validateApplicability(cfg *spec.ProjectConfig, framework core.Framework) error {
	controls := framework.Controls()
	for i := range controls {
		if !controls[i].IsManagementSystem() {
			continue
		}
		cc, ok := cfg.Controls[controls[i].ID]
		if !ok || cc.Applicability != "not_applicable" {
			continue
		}
		return fmt.Errorf("project config: controls[%q]: %q is a management-system requirement of %s "+
			"(%s) and cannot be declared not_applicable — certification is granted against the "+
			"management system, not against a subset of it",
			controls[i].ID, controls[i].ID, framework.ID(), controls[i].Name)
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
	if a == "" {
		return len(b)
	}
	if b == "" {
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

// checkAutomatedOverride rejects `evidence_mode: automated` on a policy
// that has nothing to evaluate in automated mode: no pass_when and no
// rule. Every shipped manual-only policy is like that, and the override
// used to load cleanly and then error on every run with `rule "" not
// registered` (exit 2), which names neither the config key nor the fix.
func checkAutomatedOverride(id, mode string, set *registry.Set) error {
	if mode != string(core.EvidenceModeAutomated) {
		return nil
	}
	policy, ok := set.Policies.Lookup(id)
	if !ok || policy.PassWhen != nil || policy.RuleRef != "" {
		return nil
	}
	return fmt.Errorf("project config: policies[%q].evidence_mode: %q has no automated check (no pass_when and no rule), "+
		"so it can only be evaluated from manual evidence; remove the override", id, core.EvidenceModeAutomated)
}
