package core

import "sort"

// ControlAssurance says what kind of check stands behind a control —
// the distinction the compliance score deliberately does not make.
//
// A score is a pass rate over the policies that ran, and a manual policy
// that passes counts exactly as much as an automated one. That is
// defensible arithmetic and indefensible as a headline: "a document is
// on file" and "412 resources were inspected and all conformed" are not
// the same claim. This type is what lets a surface say which it has.
type ControlAssurance string

// ControlAssurance values, strongest first.
const (
	// AssuranceAutomated means at least one policy behind the control
	// inspects live infrastructure through a source plugin.
	AssuranceAutomated ControlAssurance = "automated"
	// AssuranceManual means every policy behind the control is satisfied
	// by a document being present in the right folder, inside the
	// temporal window, and parseable. The document's contents are never
	// read — a signed risk assessment and a blank page with the right
	// filename are the same evidence to the evaluator.
	AssuranceManual ControlAssurance = "manual"
	// AssuranceNone means the framework declares the control and no
	// policy implements it. TestEveryControlHasAPolicy fails the build
	// on this for in-tree frameworks, so it should only appear for a
	// project-local framework extension.
	AssuranceNone ControlAssurance = "none"
)

// ControlCoverage is one control and what is actually behind it.
type ControlCoverage struct {
	ControlID string
	Assurance ControlAssurance
	// AutomatedPolicies and ManualPolicies count the policies of each
	// kind mapped to this control. Both are reported because the
	// assurance label deliberately hides one of them: a control with one
	// automated check and four documents is AssuranceAutomated, and a
	// reader deciding where to spend the next month deserves the mix.
	AutomatedPolicies int
	ManualPolicies    int
}

// CoverageSummary is the headline count over a set of ControlCoverage
// rows.
type CoverageSummary struct {
	Controls  int
	Automated int
	Manual    int
	Uncovered int
}

// ClassifyControls buckets every declared control by the strongest check
// behind it. Rows come back sorted by control ID, so any surface built
// on them is deterministic.
//
// One automated policy outranks any number of manual ones: the control
// is genuinely inspected, whatever else also hangs off it.
//
// Policies are attributed by PrimaryControlID, matching how every other
// single-control display surface in the tree resolves a multi-framework
// mapping. A policy naming a control the framework does not declare is
// ignored rather than inventing a row.
//
// The input is the framework catalog, so this describes what the
// framework declares — not what any particular run did. A run's own
// account of itself is PolicyResult.EvidenceMode, which is authoritative
// where the two disagree (a project can override a policy's mode).
func ClassifyControls(controls []Control, policies []Policy) []ControlCoverage {
	byID := make(map[string]*ControlCoverage, len(controls))
	out := make([]ControlCoverage, len(controls))
	for i := range controls {
		out[i] = ControlCoverage{ControlID: controls[i].ID, Assurance: AssuranceNone}
		byID[controls[i].ID] = &out[i]
	}

	for i := range policies {
		c, ok := byID[PrimaryControlID(policies[i].Controls)]
		if !ok {
			continue
		}
		if policies[i].EvidenceMode == EvidenceModeAutomated {
			c.AutomatedPolicies++
			c.Assurance = AssuranceAutomated
			continue
		}
		c.ManualPolicies++
		if c.Assurance == AssuranceNone {
			c.Assurance = AssuranceManual
		}
	}

	// Control IDs are unique within a framework, so this is a total
	// order and sort.Slice is safe.
	sort.Slice(out, func(i, j int) bool { return out[i].ControlID < out[j].ControlID })
	return out
}

// CoverageTotals reduces classified rows to the headline counts.
func CoverageTotals(rows []ControlCoverage) CoverageSummary {
	s := CoverageSummary{Controls: len(rows)}
	for i := range rows {
		switch rows[i].Assurance {
		case AssuranceAutomated:
			s.Automated++
		case AssuranceManual:
			s.Manual++
		case AssuranceNone:
			s.Uncovered++
		}
	}
	return s
}
