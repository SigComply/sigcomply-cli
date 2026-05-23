package planner

import (
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// RunPlan is the fully-resolved output of L3. The collector and
// evaluator iterate it; no further config lookups are needed at run
// time.
type RunPlan struct {
	Framework string
	Period    Period
	Policies  []PlannedPolicy
}

// Period is the audit window this run belongs to. Computed from
// (commit_time, fiscal_calendar) — see docs/architecture/01-
// conceptual-model.md §Period.
type Period struct {
	ID        string
	Start     time.Time
	End       time.Time
	TimeBasis string // "commit" or "wall_clock"
}

// PlannedPolicy is one policy with everything needed to execute it
// already resolved. Parameters and exceptions are flattened to their
// effective values so the evaluator never goes back to the config.
type PlannedPolicy struct {
	Spec       core.Policy
	Cadence    string
	Parameters map[string]any
	Bindings   map[string][]Binding
	Exception  *Exception // nil unless one applies
}

// Binding is one resolved (source instance, optional slot params)
// pair. Multiple bindings on one slot mean "union the records from
// all of them" — the evaluator merges them per slot.
type Binding struct {
	SourceID   string
	CatalogID  string // non-empty only for manual sources (e.g. manual.pdf:access_review_quarterly)
	SlotParams map[string]any
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
