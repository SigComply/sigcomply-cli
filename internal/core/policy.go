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
//
// Accepts lists every evidence type that satisfies this slot. The
// planner binds a source to the slot when source.Emits() shares at
// least one type with Accepts; multiple bindings can target the same
// slot (subject to Cardinality) and may emit different types from the
// Accepts list. Rules receive evidence grouped by slot name and may
// switch on record.Type when behavior differs per type.
//
// A slot listing more than one type is how cross-cloud /
// cross-source substitutability is expressed: an "object storage
// encrypted at rest" policy lists {s3_bucket, gcs_bucket,
// azure_blob_container} and is satisfied by any source that emits
// any of them — no policy fork, no source-side LCD payload, no
// normalization step. See docs/architecture/03-policy-spec.md §Slots.
type Slot struct {
	Accepts     []string
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
