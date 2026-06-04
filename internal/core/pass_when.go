package core

// PassWhenSpec is the declarative evaluation DSL for automated policies.
// It contains one or more clauses — one clause per slot for multi-slot
// policies, exactly one for the common single-slot case. All clauses must
// pass for the policy to pass.
//
// See docs/architecture/03-policy-spec.md §pass_when.
type PassWhenSpec struct {
	Clauses []PassWhenClause
}

// PassWhenClause is one slot's evaluation rule within a pass_when: block.
type PassWhenClause struct {
	// Slot names the slot whose records are evaluated.
	Slot string
	// Quantifier determines the aggregation semantics.
	Quantifier PassWhenQuantifier
	// Condition is the per-record test applied to records that pass the Filter.
	Condition *PassWhenCondition
	// Filter is an optional pre-condition. Records not satisfying the Filter
	// are excluded from the quantifier evaluation entirely (neither pass nor
	// fail). Nil means all records are evaluated.
	Filter *PassWhenCondition
	// ViolationMsg is a template for per-record violation messages.
	// Supports {{.field.path}} substitution against the record context.
	ViolationMsg string
	// IdentityKey is an optional field path used to deduplicate violations.
	// When set, only the first violation per unique value of this field is
	// emitted. Defaults to "id".
	IdentityKey string
	// MinPercentage is the minimum percentage (0–100) of records that must
	// satisfy the Condition. Only meaningful when Quantifier == QuantifierCount.
	MinPercentage *float64
}

// PassWhenQuantifier determines how the DSL aggregates per-record results.
type PassWhenQuantifier string

const (
	// QuantifierAll passes iff every included record satisfies the condition.
	QuantifierAll PassWhenQuantifier = "all"
	// QuantifierNone passes iff no included record satisfies the condition
	// (i.e. all records must fail it).
	QuantifierNone PassWhenQuantifier = "none"
	// QuantifierAny passes iff at least one included record satisfies the condition.
	QuantifierAny PassWhenQuantifier = "any"
	// QuantifierCount passes iff at least MinPercentage% of included records
	// satisfy the condition.
	QuantifierCount PassWhenQuantifier = "count"
)

// PassWhenCondition is a single boolean expression in the pass_when: DSL.
// It is either a leaf condition (Op + Field + Value) or a compound
// condition (Op == "all_of" or "any_of" + Conditions list).
type PassWhenCondition struct {
	// Op is the comparison operator: eq, neq, lt, lte, gt, gte, in,
	// not_in, is_set, all_of, any_of.
	Op string
	// Field is the dot-path to the field to compare, e.g. "payload.mfa_enabled"
	// or "id". Ignored for all_of / any_of. Field is always a record path;
	// "$params.<name>" is resolved only on the Value (RHS) side, not here —
	// a "$params.*" Field would be looked up as a record path and fail.
	Field string
	// Value is the RHS of the comparison for leaf operators. May be a scalar
	// (bool, int, float64, string) or a []interface{} for in / not_in.
	// A string value of the form "$params.<name>" is resolved to the parameter
	// value at evaluation time.
	Value any
	// Conditions is the sub-condition list for all_of / any_of operators.
	Conditions []*PassWhenCondition
}
