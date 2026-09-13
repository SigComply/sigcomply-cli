package core

import "time"

// RunSummarySchemaVersion is stamped on every vault-side framework
// run summary. Adding an optional field keeps the same major version;
// only a rename or a semantic change to an existing field bumps it.
// See docs/architecture/05-vault-layout.md §Schema versions.
const RunSummarySchemaVersion = "summary.v2"

// FrameworkRunSummary is the per-run, framework-level summary
// persisted at {framework}/{periodID}/run_*/summary.json. This
// shape is vault-side and may carry full-fidelity per-policy
// references; the privacy-bounded SubmissionPayload is built
// independently by the aggregator from the same []PolicyResult.
//
// Auditors read this file for the run; the framework's separate
// period summary (one per (framework, periodID), rebuilt every run
// inside that period) aggregates these into the period view.
type FrameworkRunSummary struct {
	SchemaVersion string         `json:"schema_version"`
	RunID         string         `json:"run_id"`
	Framework     string         `json:"framework"`
	PeriodID      string         `json:"period_id"`
	CompletedAt   time.Time      `json:"completed_at"`
	Policies      []PolicyResult `json:"policies"`

	// Scope is the run's estate-coverage verdict: what the operator
	// declared this project covers, and whether the run actually reached
	// it. Absent (and omitted) when no estate is declared, which is the
	// default. Typed as any so core keeps no dependency on the scope
	// package; the concrete type is *scope.Report.
	//
	// This lives here rather than on the wire deliberately. Source IDs
	// are operator-chosen and routinely embed account or environment
	// names, so the report stays vault-side, where identifiers are
	// allowed, and is covered by the run manifest's signature.
	Scope any `json:"scope,omitempty"`
}

// PeriodAggregate is the per-policy timeline summary for sub-period
// cadences. When a policy's cadence is shorter than the audit period
// (e.g., daily MFA check inside a quarterly period), the summary's
// "latest status" alone does not answer the auditor's real question
// — "did this control hold continuously throughout the period?"
//
// PeriodAggregate, when present on a policy result, answers it:
// number of evaluations, pass/fail breakdown, longest failure
// streak, longest gap between evaluations. Absent for period-aligned
// cadences (quarterly inside a quarterly period — there is only one
// data point).
//
// NOTE: nothing in the CLI populates this today, and no `sigcomply
// audit-ledger` command exists — an earlier draft of this comment
// named one. Computing it means reading the run-folder history for a
// period, which the CLI deliberately does not do: it keeps no history
// across runs (ARCHITECTURE.md Core Principle #2), and cross-run and
// cross-period reporting belongs to the Cloud dashboard. The type is
// kept as the agreed shape for that reporting, not as a promise of a
// CLI command.
type PeriodAggregate struct {
	EvaluationsInPeriod          int           `json:"evaluations_in_period"`
	PassCount                    int           `json:"pass_count"`
	FailCount                    int           `json:"fail_count"`
	LongestFailureStreak         time.Duration `json:"longest_failure_streak,omitempty"`
	FirstEvaluationAt            time.Time     `json:"first_evaluation_at,omitempty"`
	LastEvaluationAt             time.Time     `json:"last_evaluation_at,omitempty"`
	LongestGapBetweenEvaluations time.Duration `json:"longest_gap_between_evaluations,omitempty"`
}
