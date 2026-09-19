package core

import (
	"context"
	"time"
)

// Rule is the evaluation logic for a policy. Implementations may be
// hand-written Go, Rego (run via OPA), or a YAML DSL transpiled to
// Rego. Rules are pure functions over RuleInput — no I/O permitted.
type Rule interface {
	ID() string
	Evaluate(ctx context.Context, in RuleInput) (RuleResult, error)
}

// RuleInput is the read-only context handed to a rule per policy
// evaluation. Records arrive grouped by slot name.
type RuleInput struct {
	PolicyID string
	Slots    map[string][]EvidenceRecord
	Params   map[string]any
	Now      time.Time
}

// RuleResult is what a rule returns to the evaluator. Lives vault-side;
// the aggregator (L6) projects this into the privacy-bounded
// AggregatedPolicy that crosses the boundary.
type RuleResult struct {
	Status     PolicyStatus
	Violations []Violation
	Diag       map[string]any

	// Counts, when non-nil, overrides the evaluator's default
	// resources_evaluated / resources_failed arithmetic.
	//
	// The default counts records in the slots, which is right for an
	// automated policy where one record is one resource. It is wrong
	// for a fan-out manual entry, where a single record carries N
	// instances: the default would report "1 evaluated" for a check
	// that examined twelve vendors' folders. These are the two numbers
	// that cross the aggregation boundary, so getting them wrong
	// understates the work on the dashboard.
	Counts *ResourceCounts
}

// ResourceCounts is an explicit resources_evaluated / resources_failed
// pair supplied by a rule that knows better than the record arithmetic.
type ResourceCounts struct {
	Evaluated int
	Failed    int
}

// Violation is one record-level failure produced by a rule. Lives
// vault-side only — never crosses the aggregation boundary.
type Violation struct {
	ResourceID string
	Reason     string
	Details    map[string]any
}
