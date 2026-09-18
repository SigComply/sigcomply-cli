package core

import "time"

// PolicyResult is the per-policy outcome with full fidelity — includes
// violation details and resource IDs. This shape is what L7 (vault)
// persists. L6 (aggregator) projects it into the privacy-bounded
// AggregatedPolicy before any cloud submission.
//
// PolicyResult is vault-side; nothing in this struct crosses the
// aggregation boundary directly.
type PolicyResult struct {
	PolicyID           string
	Controls           []ControlRef
	Status             PolicyStatus
	Severity           Severity
	Category           string
	EffectiveParams    map[string]any
	Violations         []Violation
	ResourcesEvaluated int
	ResourcesFailed    int
	EvidenceEnvelopes  []string
	RuleVersion        string
	Diag               map[string]any

	// EvidenceMode is how this result was actually reached: automated
	// (live infrastructure was inspected) or manual (a document was
	// confirmed present in the right folder, in the temporal window,
	// and parseable — its contents were never read).
	//
	// Both modes emit StatusPass, so without this field a run resting
	// entirely on uploaded documents is indistinguishable from one that
	// verified everything. Recorded per result rather than derived from
	// the framework catalog because a project can override a policy's
	// mode, and the catalog would then describe something the run did
	// not do.
	EvidenceMode EvidenceMode

	// EvidenceModeOverridden is true when the project's config changed
	// this policy's evidence mode from the framework default — almost
	// always an automated check downgraded to a document upload. A
	// legitimate escape hatch, but one an auditor must be able to see.
	EvidenceModeOverridden bool

	// ConfiguredCadence is the cadence string in effect at this run
	// (e.g., "daily" or "every:6h"). Captured on every result so the
	// framework summary and the audit ledger can show the cadence
	// without recomputing it. Same value as in PolicyState.
	ConfiguredCadence string

	// PolicyContentHash is the SHA-256 of the canonicalized policy
	// spec plus referenced evidence-type schemas at this run.
	// Auditors comparing two runs can detect a policy/schema update
	// by comparing this field.
	PolicyContentHash string

	// NextDueAt is the wall-clock time after which the policy is due
	// to be re-evaluated under its configured cadence. Zero for
	// "continuous" / "every:0s" cadences (always due) and for
	// policies whose most recent terminal status was not pass (in
	// which case the on_fail_retry rule applies on the next run).
	NextDueAt time.Time

	// CarryForward is non-nil iff Status is StatusCarriedForward. It
	// references the prior evaluation that this run inherits from.
	// The reference is hash-tied to the original signed envelope so
	// an auditor can verify it offline without trusting the CLI.
	CarryForward *CarryForwardRef

	// PeriodAggregate, when non-nil, summarizes every evaluation of
	// this policy across the current audit period. Nothing populates
	// it today: a single run cannot know its period history, and the
	// CLI keeps no history across runs by design. See
	// PeriodAggregate's doc for why it is kept.
	PeriodAggregate *PeriodAggregate
}

// CarryForwardRef pins a carry-forward result to a specific prior
// evaluation. The pair (LastEvaluatedRun, LastEnvelopeRef) is the
// vault path to a signed envelope an auditor can re-verify
// independently; LastKnownStatus is the status that prior evaluation
// produced. SkipReason is the planner's human-readable explanation
// for why this run did not re-evaluate.
type CarryForwardRef struct {
	LastEvaluatedAt  time.Time
	LastEvaluatedRun string
	LastEnvelopeRef  string
	LastKnownStatus  PolicyStatus
	SkipReason       string
}
