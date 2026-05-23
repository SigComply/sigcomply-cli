package core

// Policy is the fully-resolved spec used by the planner and evaluator.
// Specs are loaded from policy.yaml files at L0; this is the in-memory
// shape with the rule reference still as a string ID — the registry
// resolves it to a Rule implementation at plan time.
type Policy struct {
	ID          string
	Control     string
	Description string
	Remediation string
	Severity    Severity
	Category    string
	Cadence     string
	OnPush      bool
	Slots       map[string]Slot
	Parameters  map[string]ParameterSpec
	RuleRef     string
	Tags        []string
}

// Slot is a named typed input on a policy — the interface between the
// policy and the source plugins that fulfill it.
type Slot struct {
	Type        string
	Cardinality SlotCardinality
	Required    bool
	Description string
}

// ParameterSpec describes a tunable per-project value on a policy.
// Default/Min/Max/Enum are typed `any` because the value's static type
// is named by the Type field (bool, int, string, duration, …).
type ParameterSpec struct {
	Type        string
	Default     any
	Min         any
	Max         any
	Enum        []any
	Pattern     string
	Description string
}
