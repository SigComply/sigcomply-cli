package spec

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// policySchemaVersion is the only schema_version this loader accepts.
const policySchemaVersion = "policy.v1"

// policySpecRaw is the on-disk YAML shape of a policy.yaml file. It is
// decoded with KnownFields(true), then validated and converted to
// core.Policy. See docs/architecture/03-policy-spec.md for the canonical
// spec.
type policySpecRaw struct {
	SchemaVersion string                  `yaml:"schema_version"`
	ID            string                  `yaml:"id"`
	Control       string                  `yaml:"control"`
	Severity      core.Severity           `yaml:"severity"`
	Category      string                  `yaml:"category"`
	Cadence       string                  `yaml:"cadence"`
	OnPush        *bool                   `yaml:"on_push"`
	Description   string                  `yaml:"description"`
	Remediation   string                  `yaml:"remediation"`
	Slots         map[string]slotSpecRaw  `yaml:"slots"`
	Parameters    map[string]paramSpecRaw `yaml:"parameters"`
	Rule          string                  `yaml:"rule"`
	Tags          []string                `yaml:"tags"`
}

type slotSpecRaw struct {
	// Accepts lists every evidence type that satisfies this slot. A
	// single-element list is the common case (a slot specific to one
	// evidence shape); multiple elements declare cross-source
	// substitutability — any source whose Emits() shares at least one
	// type with Accepts can bind here. See
	// docs/architecture/03-policy-spec.md §Slots.
	Accepts     []string `yaml:"accepts"`
	Cardinality string   `yaml:"cardinality"`
	Required    bool     `yaml:"required"`
	Description string   `yaml:"description"`
}

type paramSpecRaw struct {
	Type        string `yaml:"type"`
	Default     any    `yaml:"default"`
	Min         any    `yaml:"min"`
	Max         any    `yaml:"max"`
	Enum        []any  `yaml:"enum"`
	Pattern     string `yaml:"pattern"`
	ItemPattern string `yaml:"item_pattern"`
	Description string `yaml:"description"`
}

// LoadPolicy parses a policy.yaml document and returns the L1
// core.Policy with all fields populated.
//
// Out of scope at L0: verifying that `control` exists in the
// framework's control catalog, that `rule` resolves in the rule
// registry, and that each `slot.type` exists in the evidence-type
// registry. Those are cross-spec checks handled by the planner (L3).
func LoadPolicy(data []byte) (core.Policy, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return core.Policy{}, fmt.Errorf("policy spec: empty input")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var raw policySpecRaw
	if err := dec.Decode(&raw); err != nil {
		return core.Policy{}, fmt.Errorf("policy spec: parse: %w", err)
	}
	if err := validatePolicy(&raw); err != nil {
		return core.Policy{}, err
	}
	return policyFromRaw(&raw), nil
}

func policyFromRaw(raw *policySpecRaw) core.Policy {
	onPush := defaultOnPush(raw)

	slots := make(map[string]core.Slot, len(raw.Slots))
	for name, s := range raw.Slots {
		accepts := make([]string, len(s.Accepts))
		copy(accepts, s.Accepts)
		slots[name] = core.Slot{
			Accepts:     accepts,
			Cardinality: core.SlotCardinality(s.Cardinality),
			Required:    s.Required,
			Description: s.Description,
		}
	}
	params := make(map[string]core.ParameterSpec, len(raw.Parameters))
	for name := range raw.Parameters {
		p := raw.Parameters[name]
		params[name] = core.ParameterSpec{
			Type:        p.Type,
			Default:     p.Default,
			Min:         p.Min,
			Max:         p.Max,
			Enum:        p.Enum,
			Pattern:     p.Pattern,
			Description: p.Description,
		}
	}
	return core.Policy{
		ID:          raw.ID,
		Control:     raw.Control,
		Description: raw.Description,
		Remediation: raw.Remediation,
		Severity:    raw.Severity,
		Category:    raw.Category,
		Cadence:     raw.Cadence,
		OnPush:      onPush,
		Slots:       slots,
		Parameters:  params,
		RuleRef:     raw.Rule,
		Tags:        raw.Tags,
	}
}

// defaultOnPush returns OnPush honoring an explicit YAML value when
// present, falling back to the framework convention: automated
// policies default true, manual policies (any slot accepting
// signed_document) default false. The check is shape-based — the
// planner has the authoritative view, but the policy loader's defaults
// match the convention documented in 03-policy-spec.md §Custom
// policies.
func defaultOnPush(raw *policySpecRaw) bool {
	if raw.OnPush != nil {
		return *raw.OnPush
	}
	for _, s := range raw.Slots {
		for _, t := range s.Accepts {
			if t == "signed_document" {
				return false
			}
		}
	}
	return true
}

func validatePolicy(raw *policySpecRaw) error {
	if err := expectSchemaVersion(raw.SchemaVersion, policySchemaVersion, "policy spec"); err != nil {
		return err
	}
	if err := validatePolicyRequiredScalars(raw); err != nil {
		return err
	}
	if err := validatePolicyEnums(raw); err != nil {
		return err
	}
	if err := validatePolicySlots(raw); err != nil {
		return err
	}
	return validatePolicyParameters(raw)
}

func validatePolicyRequiredScalars(raw *policySpecRaw) error {
	if raw.ID == "" {
		return fmt.Errorf("policy spec: missing required field \"id\"")
	}
	if raw.Control == "" {
		return fmt.Errorf("policy spec %q: missing required field \"control\"", raw.ID)
	}
	if raw.Description == "" {
		return fmt.Errorf("policy spec %q: missing required field \"description\"", raw.ID)
	}
	if raw.Rule == "" {
		return fmt.Errorf("policy spec %q: missing required field \"rule\"", raw.ID)
	}
	if raw.Severity == "" {
		return fmt.Errorf("policy spec %q: missing required field \"severity\"", raw.ID)
	}
	if raw.Cadence == "" {
		return fmt.Errorf("policy spec %q: missing required field \"cadence\"", raw.ID)
	}
	return nil
}

func validatePolicyEnums(raw *policySpecRaw) error {
	if !isValidSeverity(raw.Severity) {
		return fmt.Errorf("policy spec %q: invalid severity %q (want info|low|medium|high|critical)", raw.ID, raw.Severity)
	}
	if !isValidCadence(raw.Cadence) {
		return fmt.Errorf("policy spec %q: invalid cadence %q (want continuous|hourly|daily|weekly|monthly|quarterly|annual)", raw.ID, raw.Cadence)
	}
	return nil
}

func validatePolicySlots(raw *policySpecRaw) error {
	if len(raw.Slots) == 0 {
		return fmt.Errorf("policy spec %q: \"slots\" must declare at least one slot", raw.ID)
	}
	for name, s := range raw.Slots {
		if len(s.Accepts) == 0 {
			return fmt.Errorf("policy spec %q: slot %q missing required field \"accepts\" (list at least one evidence type)", raw.ID, name)
		}
		for i, t := range s.Accepts {
			if t == "" {
				return fmt.Errorf("policy spec %q: slot %q accepts[%d] is empty", raw.ID, name, i)
			}
		}
		if s.Cardinality == "" {
			return fmt.Errorf("policy spec %q: slot %q missing required field \"cardinality\"", raw.ID, name)
		}
		if !isValidCardinality(core.SlotCardinality(s.Cardinality)) {
			return fmt.Errorf("policy spec %q: slot %q invalid cardinality %q (want exactly-one|at-most-one|one-or-more|optional)", raw.ID, name, s.Cardinality)
		}
	}
	return nil
}

func validatePolicyParameters(raw *policySpecRaw) error {
	for name := range raw.Parameters {
		p := raw.Parameters[name]
		if p.Type == "" {
			return fmt.Errorf("policy spec %q: parameter %q missing required field \"type\"", raw.ID, name)
		}
		if !isValidParamType(p.Type) {
			return fmt.Errorf("policy spec %q: parameter %q invalid type %q", raw.ID, name, p.Type)
		}
	}
	return nil
}

var validCadences = map[string]struct{}{
	"continuous": {},
	"hourly":     {},
	"daily":      {},
	"weekly":     {},
	"monthly":    {},
	"quarterly":  {},
	"annual":     {},
}

func isValidCadence(c string) bool {
	_, ok := validCadences[c]
	return ok
}

func isValidCardinality(c core.SlotCardinality) bool {
	switch c {
	case core.SlotExactlyOne, core.SlotAtMostOne, core.SlotOneOrMore, core.SlotOptional:
		return true
	}
	return false
}

var validParamTypes = map[string]struct{}{
	"bool":           {},
	"int":            {},
	"float":          {},
	"string":         {},
	"duration":       {},
	"date":           {},
	"list_of_string": {},
	"list_of_int":    {},
}

func isValidParamType(t string) bool {
	_, ok := validParamTypes[t]
	return ok
}
