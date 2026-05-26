package core

// Severity is the policy's display severity. Set on the policy spec;
// a rule cannot override it. If a single policy needs variable
// severity, split it into multiple policies.
type Severity string

// Severity values, in ascending order of urgency.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// PolicyStatus is the per-policy outcome of a run.
type PolicyStatus string

// PolicyStatus values. `pass`/`fail` are the rule outcomes; `skip` /
// `error` / `na` / `waived` are evaluator/exception-driven states.
// `carried_forward` indicates the policy was NOT evaluated in this
// run — the result references a prior signed envelope. See
// docs/architecture/11-cadence-model.md §Carry-forward.
const (
	StatusPass           PolicyStatus = "pass"
	StatusFail           PolicyStatus = "fail"
	StatusSkip           PolicyStatus = "skip"
	StatusError          PolicyStatus = "error"
	StatusNA             PolicyStatus = "na"
	StatusWaived         PolicyStatus = "waived"
	StatusCarriedForward PolicyStatus = "carried_forward"
)

// SlotCardinality declares how many sources a slot may bind.
type SlotCardinality string

// SlotCardinality values. See 03-policy-spec.md §Slots for the
// project-binding rules each cardinality imposes.
const (
	SlotExactlyOne SlotCardinality = "exactly-one"
	SlotAtMostOne  SlotCardinality = "at-most-one"
	SlotOneOrMore  SlotCardinality = "one-or-more"
	SlotOptional   SlotCardinality = "optional"
)
