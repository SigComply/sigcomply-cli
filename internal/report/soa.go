package report

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// SoA row statuses. "excluded" is not a failure: a well-reasoned
// exclusion with a recorded justification is exactly what a Statement of
// Applicability is for.
const (
	soaExcluded       = "excluded"
	soaImplemented    = "implemented"
	soaPartial        = "partially implemented"
	soaNotImplemented = "not implemented"
	soaNotEvaluated   = "not evaluated"
)

// buildSoA assembles a Statement of Applicability.
//
// ISO/IEC 27001:2022 6.1.3 d asks for four things about the control
// catalog: which controls are necessary, why each is included, whether
// it is implemented, and why any were left out. SigComply already holds
// all four — the catalog in the framework, the applicability decision
// and its reasoning in the project config, the implementation status in
// the vault — and until now had no surface that joined them, so the one
// document a Stage 1 auditor asks for first had to be maintained by
// hand alongside the tool that knew the answer.
//
// Only catalog controls appear. A management-system requirement is not
// selectable — an organization cannot decline to have an internal audit
// program — so listing ISO's clauses 4-10 here would invite exactly
// the exclusion the planner refuses to honor.
//
// Status is derived from the period's results, never asserted: a
// control whose policies did not run this period reports "not
// evaluated" rather than borrowing a pass from the catalog.
func buildSoA(
	ctx context.Context,
	v core.Vault,
	runs []runRecord,
	controls []core.Control,
	policies []core.Policy,
	controlConfigs map[string]spec.ControlConfig,
) (*SoAView, error) {
	results, err := latestResultsByPolicy(ctx, v, runs)
	if err != nil {
		return nil, err
	}

	classified := core.ClassifyControls(controls, effectiveModes(policies, results))
	assurance := make(map[string]core.ControlCoverage, len(classified))
	for i := range classified {
		assurance[classified[i].ControlID] = classified[i]
	}
	policiesByControl := groupPoliciesByControl(policies)

	catalog, mgmtSystem := partitionByKind(controls)
	out := &SoAView{ManagementSystem: len(mgmtSystem), Rows: make([]SoARow, 0, len(catalog))}
	for i := range catalog {
		row := soaRow(&catalog[i], policiesByControl[catalog[i].ID], assurance[catalog[i].ID], results, controlConfigs[catalog[i].ID])
		out.Rows = append(out.Rows, row)
		tallySoARow(out, &row)
	}
	sort.Slice(out.Rows, func(a, b int) bool { return out.Rows[a].ControlID < out.Rows[b].ControlID })
	out.Controls = len(out.Rows)
	out.Note = soaNote(out)
	return out, nil
}

// soaRow renders one catalog control as a Statement of Applicability
// entry.
func soaRow(
	c *core.Control,
	policies []core.Policy,
	cov core.ControlCoverage,
	results map[string]core.PolicyResult,
	cfg spec.ControlConfig,
) SoARow {
	row := SoARow{
		ControlID:  c.ID,
		Name:       c.Name,
		Applicable: cfg.Applicability != "not_applicable",
		Assurance:  string(cov.Assurance),
		ApprovedBy: cfg.ApprovedBy,
		Policies:   policyIDs(policies),
	}
	if cov.Assurance == "" {
		row.Assurance = string(core.AssuranceNone)
	}

	if !row.Applicable {
		row.Status = soaExcluded
		row.Justification = cfg.Reason
		return row
	}
	row.Justification = strings.TrimSpace(cfg.Justification)
	if row.Justification == "" {
		row.Justification = defaultJustification(cov)
		row.JustificationDerived = true
	}
	row.Status, row.Evaluated = soaStatus(policies, results)
	return row
}

// soaStatus rolls this period's results up into the implementation
// verdict ISO asks for. Anything short of "every check that ran passed"
// is reported as short of implemented — a partially implemented control
// that reads as implemented is the failure mode worth avoiding.
//
// "That ran" is load-bearing and decides the two interesting statuses:
// an `na` policy never ran, so it is left out of the roll-up entirely
// (a control with nothing but `na` policies reports "not evaluated"),
// while a carried-forward policy did run — in an earlier period, and it
// passed — so it counts as met.
func soaStatus(policies []core.Policy, results map[string]core.PolicyResult) (status string, evaluated int) {
	passed := 0
	for i := range policies {
		r, ok := results[policies[i].ID]
		if !ok {
			continue
		}
		// `na` is a check that never ran — the evaluator short-circuits
		// before the rule — so it neither implements the control nor
		// fails it. Counting it as met made the documented remedy for a
		// control you cannot satisfy read as "implemented" on the one
		// document an auditor reads as an assertion; counting it as
		// unmet would be the opposite lie. It abstains.
		if r.Status == core.StatusNA {
			continue
		}
		evaluated++
		switch r.Status {
		// Carry-forward is a pass: it points at a prior passing envelope
		// and is in the compliance score's numerator and the coverage
		// view's pass rank. The SoA was the only surface that called a
		// control whose checks were simply not due yet "not implemented".
		case core.StatusPass, core.StatusWaived, core.StatusCarriedForward:
			passed++
		}
	}
	switch {
	case evaluated == 0:
		return soaNotEvaluated, 0
	case passed == evaluated:
		return soaImplemented, evaluated
	case passed == 0:
		return soaNotImplemented, evaluated
	default:
		return soaPartial, evaluated
	}
}

// defaultJustification describes why a control is included when the
// operator has not said so themselves. It is accurate and generic, and
// says which it is: an auditor can tell a reasoned inclusion from a
// default one, rather than reading boilerplate as deliberation.
func defaultJustification(cov core.ControlCoverage) string {
	switch cov.Assurance {
	case core.AssuranceAutomated:
		return fmt.Sprintf("Applicable — no exclusion declared. Verified by %s.",
			countPhrase(cov.AutomatedPolicies, "automated check", "automated checks")+
				manualSuffix(cov.ManualPolicies))
	case core.AssuranceManual:
		return fmt.Sprintf("Applicable — no exclusion declared. Evidenced by %s.",
			countPhrase(cov.ManualPolicies, "manual evidence item", "manual evidence items"))
	default:
		return "Applicable — no exclusion declared. No check implements this control."
	}
}

func manualSuffix(manual int) string {
	if manual == 0 {
		return ""
	}
	return " and " + countPhrase(manual, "manual evidence item", "manual evidence items")
}

func countPhrase(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// soaNote states the two things a reader of this table must not
// misread: what it deliberately omits, and that an untested control is
// not a passing one.
func soaNote(v *SoAView) string {
	parts := []string{}
	if v.ManagementSystem > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d management-system requirements (clauses 4-10) are outside the Statement of Applicability and cannot be excluded; see report --view coverage",
			v.ManagementSystem))
	}
	if v.NotEvaluated > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d applicable controls produced no result this period — not evaluated is not implemented",
			v.NotEvaluated))
	}
	if v.Derived > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d inclusions carry a derived justification; set controls.<id>.justification to record the organization's own reasoning",
			v.Derived))
	}
	return strings.Join(parts, ". ")
}

func tallySoARow(out *SoAView, r *SoARow) {
	if !r.Applicable {
		out.Excluded++
		return
	}
	out.Applicable++
	if r.JustificationDerived {
		out.Derived++
	}
	switch r.Status {
	case soaImplemented:
		out.Implemented++
	case soaPartial:
		out.Partial++
	case soaNotImplemented:
		out.NotImplemented++
	default:
		out.NotEvaluated++
	}
}

func policyIDs(policies []core.Policy) []string {
	if len(policies) == 0 {
		return nil
	}
	out := make([]string, 0, len(policies))
	for i := range policies {
		out = append(out, policies[i].ID)
	}
	sort.Strings(out)
	return out
}
