package core

// Severity is the policy's display severity. Set on the policy spec;
// a rule cannot override it. If a single policy needs variable
// severity, split it into multiple policies.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// PolicyStatus is the per-policy outcome of a run.
type PolicyStatus string

const (
	StatusPass   PolicyStatus = "pass"
	StatusFail   PolicyStatus = "fail"
	StatusSkip   PolicyStatus = "skip"
	StatusError  PolicyStatus = "error"
	StatusNA     PolicyStatus = "na"
	StatusWaived PolicyStatus = "waived"
)

// SlotCardinality declares how many sources a slot may bind.
type SlotCardinality string

const (
	SlotExactlyOne SlotCardinality = "exactly-one"
	SlotAtMostOne  SlotCardinality = "at-most-one"
	SlotOneOrMore  SlotCardinality = "one-or-more"
	SlotOptional   SlotCardinality = "optional"
)
