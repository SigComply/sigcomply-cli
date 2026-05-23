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
}

// Violation is one record-level failure produced by a rule. Lives
// vault-side only — never crosses the aggregation boundary.
type Violation struct {
	ResourceID string
	Reason     string
	Details    map[string]any
}
