package planner

import (
	"fmt"
	"sort"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// RiskReviewMaxAge is how long a risk may go un-reassessed before the
// register is reported as stale.
//
// This is a backstop heuristic, not the standard's requirement. ISO/IEC
// 27001 8.2 says assessments happen "at planned intervals or when
// significant changes are proposed or occur" and defines no interval at
// all — the interval is the organization's to set, and the
// nonconformity is failing to meet the one they set themselves. The CLI
// cannot know that number, so it does not pretend to: it warns only at a
// threshold nobody's declared cycle would legitimately exceed.
//
// Eighteen months rather than twelve for exactly that reason. An annual
// cycle is the norm, and twelve would warn on every honest register
// during the weeks between the anniversary and the review actually
// happening. Eighteen leaves that alone and still catches a register
// nobody has revisited in three years — the case this exists to find,
// and a documented lead-auditor finding.
const RiskReviewMaxAge = 18 * 30 * 24 * time.Hour

// RiskWarnings reports the non-fatal findings about experimental.risks:
// unrecognized subkeys, risks naming a control the framework does not
// have, and risks nobody has reassessed inside the review window.
//
// The second is the one that matters. A risk names its treating controls
// as free text, and a typo — "A.8.07" for "A.8.7" — simply fails to join
// in the Statement of Applicability. The row renders with no risk beside
// it and nothing says the operator meant otherwise, which is the same
// silent-typo failure that `experimental.roster.aliases` reports rather
// than ignores.
//
// Warning, never error. Everything fatal about the block already failed
// at config load; what is left is advice about content, and a register
// is the operator's own document. A stale assessment is a finding for
// their auditor, not a reason to fail their build.
//
// Silent when the register is undeclared: a project that never adopted
// experimental.risks is not missing anything.
func RiskWarnings(cfg *spec.ProjectConfig, controls []core.Control, periodStart time.Time) []string {
	reg, err := spec.LoadRiskRegister(cfg)
	if err != nil || reg == nil {
		return nil
	}

	var out []string
	for _, k := range reg.UnknownKeys {
		out = append(out, fmt.Sprintf("ignoring unrecognized key experimental.risks.%s", k))
	}
	out = append(out, unknownControlWarnings(reg, controls)...)
	out = append(out, staleRiskWarnings(reg, periodStart)...)
	return out
}

// unknownControlWarnings names risks that treat a control the framework
// does not define. Skipped entirely when no catalog was supplied —
// "unknown" is unknowable without one, and guessing would warn about
// every control on every run.
func unknownControlWarnings(reg *spec.RiskRegister, controls []core.Control) []string {
	if len(controls) == 0 {
		return nil
	}
	known := make(map[string]struct{}, len(controls))
	for i := range controls {
		known[controls[i].ID] = struct{}{}
	}
	byControl := reg.ControlRisks()
	var out []string
	for _, c := range reg.DeclaredControls() {
		if _, ok := known[c]; ok {
			continue
		}
		out = append(out, fmt.Sprintf("risk(s) %v name control %q, which this framework does not define; the Statement of Applicability cannot cite them against it (check the control ID)",
			byControl[c], c))
	}
	return out
}

// staleRiskWarnings names risks last assessed more than RiskReviewMaxAge
// before the period began.
//
// Fail-open on anything unparseable or absent, like assuranceStale: the
// loader has already rejected malformed dates, so treating a blank here
// as stale would warn about a register that is merely new.
func staleRiskWarnings(reg *spec.RiskRegister, periodStart time.Time) []string {
	if periodStart.IsZero() {
		return nil
	}
	cutoff := periodStart.Add(-RiskReviewMaxAge)
	var stale []string
	for i := range reg.Risks {
		r := &reg.Risks[i]
		at, err := time.Parse("2006-01-02", r.AssessedAt)
		if err != nil || at.After(cutoff) {
			continue
		}
		stale = append(stale, fmt.Sprintf("%s (last assessed %s)", r.ID, r.AssessedAt))
	}
	if len(stale) == 0 {
		return nil
	}
	sort.Strings(stale)
	return []string{fmt.Sprintf("%d risk(s) have not been reassessed in %d months, so the register no longer reflects a current assessment: %v",
		len(stale), int(RiskReviewMaxAge.Hours()/(24*30)), stale)}
}
