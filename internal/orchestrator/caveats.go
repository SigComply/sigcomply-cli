package orchestrator

import (
	"sort"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// emitSourceCaveatWarnings names the policies being graded partly on a value
// the bound source told us it never measured.
//
// The planner binds every configured source whose Emits() intersects a slot,
// and every ordinary slot is one-or-more, so nothing forces a choice between
// two identity sources. On the estate this matters most for — an IdP
// SCIM-synced into AWS Identity Center — both bind the MFA policies and their
// records are unioned: the Identity Center users fail on a hardcoded false
// while the Okta records beside them carry the true answer for the same
// people. The run is not wrong, but it is not measuring what the control
// asks, and until now nothing said so.
//
// Non-fatal, and deliberately not a status: a caveat never changes a verdict,
// a count, or the submission payload. It is the operator's cue to pin the
// slot — or to accept a real finding.
func emitSourceCaveatWarnings(logger *log.Logger, plan *planner.RunPlan) {
	if logger == nil || plan == nil {
		return
	}
	// Group by the (source, field) pair rather than per policy: one
	// misbound identity source trips every MFA policy at once, and six
	// near-identical lines would bury the one fact that matters.
	type key struct{ source, field, evidenceType, slot, detail string }
	grouped := map[key][]string{}
	alternatives := map[key][]string{}

	for i := range plan.Policies {
		pp := &plan.Policies[i]
		for _, c := range pp.SourceCaveats {
			k := key{c.SourceID, c.Field, c.EvidenceType, c.Slot, c.Detail}
			grouped[k] = append(grouped[k], pp.Spec.ID)
			alternatives[k] = c.Alternatives
		}
	}
	if len(grouped) == 0 {
		return
	}

	keys := make([]key, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		return keys[i].field < keys[j].field
	})

	for _, k := range keys {
		policies := grouped[k]
		sort.Strings(policies)
		logger.Warnf("source-caveat: %s cannot verify %s.%s — %s", k.source, k.evidenceType, k.field, k.detail)
		logger.Warnf("source-caveat: %d policy/policies read that field from this source: %s",
			len(policies), strings.Join(policies, ", "))
		if alts := alternatives[k]; len(alts) > 0 {
			// The remedy only exists when something else on the slot can
			// answer. Name the exact YAML, because "add a bindings: pin" is
			// the kind of advice that sends people to the docs.
			logger.Warnf("source-caveat: %s also bound to slot %q and not caveated here; "+
				"pin the slot to stop unioning an unverifiable value with a real one:",
				strings.Join(alts, ", "), k.slot)
			logger.Warnf("source-caveat:\n    policies:\n      %s:\n        bindings:\n          %s: [%s]",
				policies[0], k.slot, strings.Join(alts, ", "))
		} else {
			logger.Warnf("source-caveat: no other source on slot %q can answer it, so this is a real "+
				"finding rather than a binding mistake — wire an identity source that can, or declare an exception",
				k.slot)
		}
	}
}
