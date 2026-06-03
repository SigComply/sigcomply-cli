package planner

import (
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// RunPlan is the fully-resolved output of L3. The collector and
// evaluator iterate it; no further config lookups are needed at run
// time.
//
// PlannedPolicy entries with ShouldEvaluate=false are present in the
// plan so the orchestrator can emit a carry-forward result for each,
// but the collector and evaluator skip them.
type RunPlan struct {
	Framework string
	Period    Period
	Policies  []PlannedPolicy
}

// Period is the audit window this run belongs to. Computed from
// (commit_time, fiscal_calendar) — see docs/architecture/01-
// conceptual-model.md §Period.
//
// PriorID is the ID of the immediately preceding period under the same
// calendar (e.g. 2026-Q2 → 2026-Q1, FY2026 → FY2025). Empty when no
// prior period exists in the configured custom calendar. Plugins use
// it to compare against the prior period's evidence — currently the
// manual.pdf plugin reads it to detect copy-paste of last period's PDF.
type Period struct {
	ID        string
	PriorID   string
	Start     time.Time
	End       time.Time
	TimeBasis string // "commit" or "wall_clock"
}

// PlannedPolicy is one policy with everything needed to execute it
// already resolved. Parameters and exceptions are flattened to their
// effective values so the evaluator never goes back to the config.
//
// ShouldEvaluate is the per-policy gate decided by the planner from
// the policy's cadence, its on_fail_retry state, the content-hash of
// the current policy bundle vs the prior run, and the operator's
// filter overrides. When false, the orchestrator emits a carry-
// forward result.json that references PriorState.LastEnvelopeRef.
//
// PriorState is the previously-persisted state for this policy, or
// nil for never-evaluated policies. The orchestrator uses it for
// carry-forward emission and for the run-summary's freshness view.
//
// ContentHash is the SHA-256 of the canonicalized policy spec + its
// referenced evidence-type schemas at plan time. Compared against
// PriorState.LastPolicyHash to detect bundle updates that
// invalidate prior evaluations.
type PlannedPolicy struct {
	Spec       core.Policy
	Cadence    string
	Parameters map[string]any
	Bindings   map[string][]Binding
	Exception  *Exception // nil unless one applies

	ShouldEvaluate bool
	SkipReason     string // empty when ShouldEvaluate is true

	// EvidenceModeOverridden is true when the project config's
	// policy_overrides section changed this policy's evidence_mode from
	// what the framework spec declared. Surfaced in result.json so
	// auditors can see which policies are running in an overridden mode.
	EvidenceModeOverridden bool

	// CoverageGaps lists version-skew near-misses: required slots that
	// resolved to zero bindings while a configured source emits a
	// different *version* of a type the slot accepts. Such policies are
	// silently skipped at evaluation and drop out of the compliance
	// score; the orchestrator warns the operator. Empty for the common
	// case. See CoverageGap.
	CoverageGaps []CoverageGap

	PriorState  *core.PolicyState
	ContentHash string
}

// CoverageGap flags a required slot that resolved to zero bindings even
// though a configured source emits a *sibling version* of a type the
// slot accepts — for example, the slot accepts directory_user.v2 but a
// configured okta source emits directory_user (v1). The slot cannot bind
// such a source, so the policy is silently skipped at evaluation
// (requiredSlotsPopulated → StatusSkip) and disappears from the
// compliance-score denominator, hiding the gap. The planner records the
// near-miss so the orchestrator can surface it as an explicit warning.
//
// This is deliberately NOT a hard error: a version may genuinely be
// unable to answer a policy (the admin-MFA check needs v2-only fields
// that v1 cannot supply), so the legitimate fix is sometimes "leave it
// skipped", sometimes "extend accepts:", and sometimes "wire a
// v2-capable source" — the operator decides.
type CoverageGap struct {
	Slot        string   // the unbound required slot
	Accepts     []string // evidence types the slot accepts
	Source      string   // configured source ID emitting a sibling version
	SourceEmits []string // the sibling (family-matching but unaccepted) types it emits
}

// Binding is one resolved (source instance, optional slot params)
// pair. Multiple bindings on one slot mean "union the records from
// all of them" — the evaluator merges them per slot.
//
// AcceptedTypes is the intersection of the slot's Accepts list and
// the source's Emits() list, computed at plan time. The collector
// passes it through SlotRequest.AcceptedTypes so the plugin knows
// which of its emitted types the slot will accept. A binding always
// has at least one AcceptedTypes entry (the planner rejects a
// binding whose intersection is empty).
type Binding struct {
	SourceID      string
	AcceptedTypes []string
	CatalogID     string // non-empty only for manual sources (e.g. manual.pdf:access_review_quarterly)
	SlotParams    map[string]any
}

// Exception is the resolved waiver / N/A declaration applied to a
// policy. The evaluator uses State to short-circuit (na) or re-classify
// failures (waived).
type Exception struct {
	State           core.PolicyStatus // StatusWaived or StatusNA
	Reason          string
	ResourceID      string
	ResourcePattern string
	ApprovedBy      string
	ApprovedAt      string
	ExpiresAt       string
}
