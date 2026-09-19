package report

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// buildCoverage answers "what is actually behind the green?" for every
// control the framework declares.
//
// Two sources are joined. The control universe and the policies mapped
// to it come from the framework catalog, passed in by the command layer
// so this package keeps its "pure reader of vault bytes" property. What
// happened in this period comes from the latest run's result files.
//
// Where a run recorded its own evidence mode, that is authoritative: a
// project can reconfigure a policy away from the framework's declared
// mode, and describing the control by the catalog alone would then
// describe something the run did not do.
func buildCoverage(ctx context.Context, v core.Vault, runs []runRecord, controls []core.Control, policies []core.Policy) (*CoverageView, error) {
	out := &CoverageView{}

	results, err := latestResultsByPolicy(ctx, v, runs)
	if err != nil {
		return nil, err
	}

	// Catalog controls and management-system requirements are counted
	// apart. Blending them makes the headline read better every time
	// the honest gap is closed — 93/93 Annex A becomes 109/109 "controls"
	// the moment sixteen clause requirements with no evidence on file
	// are added — which is the exact drift this view exists to catch.
	catalog, mgmtSystem := partitionByKind(controls)
	out.ManagementSystem = len(mgmtSystem)

	// The catalog's view of each control, then the run's corrections.
	effective := effectiveModes(policies, results)
	classified := core.ClassifyControls(catalog, effective)
	policiesByControl := groupPoliciesByControl(policies)

	out.Rows = make([]CoverageRow, 0, len(classified))
	for i := range classified {
		out.Rows = append(out.Rows, coverageRow(&classified[i], policiesByControl[classified[i].ControlID], results))
	}

	totals := core.CoverageTotals(classified)
	out.Controls, out.Automated, out.Manual, out.Uncovered = totals.Controls, totals.Automated, totals.Manual, totals.Uncovered

	// Management-system requirements get rows too — they are the point
	// of the view, not an appendix — but their own counters, so a
	// reader can never mistake an ISMS document on file for a control
	// that was inspected.
	msClassified := core.ClassifyControls(mgmtSystem, effective)
	for i := range msClassified {
		row := coverageRow(&msClassified[i], policiesByControl[msClassified[i].ControlID], results)
		row.ManagementSystem = true
		out.Rows = append(out.Rows, row)
	}
	sort.Slice(out.Rows, func(a, b int) bool { return out.Rows[a].ControlID < out.Rows[b].ControlID })

	for i := range out.Rows {
		if out.Rows[i].ManagementSystem {
			if out.Rows[i].Status == statusPass {
				out.ManagementSystemOnFile++
			}
			continue
		}
		tallyRow(out, &out.Rows[i])
	}
	return out, nil
}

// partitionByKind splits a framework's controls into the selectable
// catalog and the management-system requirements.
func partitionByKind(controls []core.Control) (catalog, mgmtSystem []core.Control) {
	catalog = make([]core.Control, 0, len(controls))
	for i := range controls {
		if controls[i].IsManagementSystem() {
			mgmtSystem = append(mgmtSystem, controls[i])
			continue
		}
		catalog = append(catalog, controls[i])
	}
	return catalog, mgmtSystem
}

// tallyRow folds one row into the view's headline counts.
func tallyRow(out *CoverageView, r *CoverageRow) {
	if r.Evaluated > 0 {
		out.Evaluated++
	} else {
		out.NotEvaluated++
	}
	if r.Overridden {
		out.Overridden++
	}
	if r.Assurance != string(core.AssuranceManual) {
		return
	}
	if r.Status == statusPass {
		out.ManualOnFile++
		return
	}
	out.ManualMissing++
}

const (
	statusPass         = "pass"
	statusNotEvaluated = "not evaluated"
)

// effectiveModes returns the policies with each one's evidence mode
// replaced by the mode the run actually used, where the run recorded
// one. Results written before the mode was recorded carry an empty
// value and leave the catalog's declaration standing.
func effectiveModes(policies []core.Policy, results map[string]core.PolicyResult) []core.Policy {
	out := make([]core.Policy, len(policies))
	copy(out, policies)
	for i := range out {
		if r, ok := results[out[i].ID]; ok && r.EvidenceMode != "" {
			out[i].EvidenceMode = r.EvidenceMode
		}
	}
	return out
}

func groupPoliciesByControl(policies []core.Policy) map[string][]core.Policy {
	out := map[string][]core.Policy{}
	for i := range policies {
		id := core.PrimaryControlID(policies[i].Controls)
		out[id] = append(out[id], policies[i])
	}
	return out
}

// coverageRow renders one control: its assurance, the mix of checks
// behind it, and what this period's runs made of them.
func coverageRow(c *core.ControlCoverage, policies []core.Policy, results map[string]core.PolicyResult) CoverageRow {
	row := CoverageRow{
		ControlID:         c.ControlID,
		Assurance:         string(c.Assurance),
		AutomatedPolicies: c.AutomatedPolicies,
		ManualPolicies:    c.ManualPolicies,
		Policies:          len(policies),
		Status:            statusNotEvaluated,
	}

	var worst core.PolicyStatus
	var notes []string
	for i := range policies {
		r, ok := results[policies[i].ID]
		if !ok {
			continue
		}
		row.Evaluated++
		if r.EvidenceModeOverridden {
			row.Overridden = true
		}
		if worst == "" || statusRank(r.Status) > statusRank(worst) {
			worst = r.Status
		}
		if reason := core.ResultReason(&r); reason != "" {
			notes = append(notes, reason)
		}
	}

	if worst != "" {
		row.Status = string(worst)
	}
	row.Note = coverageNote(c, policies, row.Evaluated, notes)
	return row
}

// coverageNote explains a row that would otherwise leave a reader
// guessing — why nothing ran, or what went wrong.
func coverageNote(c *core.ControlCoverage, policies []core.Policy, evaluated int, reasons []string) string {
	if evaluated == 0 {
		if c.Assurance == core.AssuranceNone {
			return "no policy implements this control"
		}
		// Not alarming on its own: cadence is independent of the audit
		// period, so an annual control legitimately produces no result
		// in three quarters out of four. Naming the cadence lets a
		// reader tell that apart from a daily check that never ran.
		if cad := distinctCadences(policies); cad != "" {
			return fmt.Sprintf("no policy ran in this period (cadence: %s)", cad)
		}
		return "no policy ran in this period"
	}
	if len(reasons) > 0 {
		return reasons[0]
	}
	return ""
}

// distinctCadences joins the sorted distinct cadences of a control's
// policies, so the note is stable across runs.
func distinctCadences(policies []core.Policy) string {
	seen := map[string]struct{}{}
	for i := range policies {
		if policies[i].Cadence != "" {
			seen[policies[i].Cadence] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// statusRank orders statuses by how much attention they deserve, so a
// control's roll-up reports its worst outcome rather than an arbitrary
// one. error outranks fail because an errored policy is an unevaluated
// control that still counts against the score.
func statusRank(s core.PolicyStatus) int {
	switch s {
	case core.StatusError:
		return 5
	case core.StatusFail:
		return 4
	case core.StatusSkip:
		return 3
	case core.StatusNA, core.StatusWaived:
		return 2
	default: // pass, carried_forward
		return 1
	}
}

// latestResultsByPolicy returns the latest result for each policy across
// the period's runs — the same latest-wins rule the latest view applies,
// so the two views can never disagree about what happened.
func latestResultsByPolicy(ctx context.Context, v core.Vault, runs []runRecord) (map[string]core.PolicyResult, error) {
	out := map[string]core.PolicyResult{}
	for i := range runs {
		if runs[i].Manifest.RunID == "" {
			continue
		}
		bodies, err := listPolicyResults(ctx, v, runs[i].Path)
		if err != nil {
			return nil, err
		}
		for policyID, body := range bodies {
			var r core.PolicyResult
			if err := json.Unmarshal(body, &r); err != nil {
				// An unreadable result.json is skipped rather than
				// fatal, matching how the other views degrade.
				continue
			}
			out[policyID] = r
		}
	}
	return out, nil
}
