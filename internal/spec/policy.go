package spec

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// policySchemaVersion is the only schema_version this loader accepts.
const policySchemaVersion = "policy.v1"

// ManualSlotName is the synthetic slot name the planner creates for
// manual policies. The collector and evaluator use it as the key in
// RecordsByPolicy[policyID].
const ManualSlotName = "_manual"

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
	EvidenceMode  string                  `yaml:"evidence_mode"`
	CatalogEntry  string                  `yaml:"catalog_entry"`
	PassWhen      yaml.Node               `yaml:"pass_when"`
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

// passWhenClauseRaw is the intermediate raw shape of one pass_when clause.
type passWhenClauseRaw struct {
	Slot          string                `yaml:"slot"`
	Quantifier    string                `yaml:"quantifier"`
	Condition     *passWhenConditionRaw `yaml:"condition"`
	Filter        *passWhenConditionRaw `yaml:"filter"`
	ViolationMsg  string                `yaml:"violation_message"`
	IdentityKey   string                `yaml:"identity_key"`
	MinPercentage *float64              `yaml:"min_percentage"`
}

// passWhenConditionRaw is the intermediate raw shape of one condition node.
type passWhenConditionRaw struct {
	Op         string                  `yaml:"op"`
	Field      string                  `yaml:"field"`
	Value      any                     `yaml:"value"`
	Conditions []*passWhenConditionRaw `yaml:"conditions"`
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
	return policyFromRaw(&raw)
}

func policyFromRaw(raw *policySpecRaw) (core.Policy, error) {
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

	var passWhen *core.PassWhenSpec
	if raw.PassWhen.Kind != 0 {
		var err error
		passWhen, err = parsePassWhen(&raw.PassWhen)
		if err != nil {
			return core.Policy{}, fmt.Errorf("policy spec %q: pass_when: %w", raw.ID, err)
		}
	}

	return core.Policy{
		ID:           raw.ID,
		Control:      raw.Control,
		Description:  raw.Description,
		Remediation:  raw.Remediation,
		Severity:     raw.Severity,
		Category:     raw.Category,
		Cadence:      raw.Cadence,
		OnPush:       onPush,
		Slots:        slots,
		Parameters:   params,
		RuleRef:      raw.Rule,
		Tags:         raw.Tags,
		EvidenceMode: core.EvidenceMode(raw.EvidenceMode),
		PassWhen:     passWhen,
		CatalogEntry: raw.CatalogEntry,
	}, nil
}

// defaultOnPush returns OnPush honoring an explicit YAML value when
// present, falling back to the framework convention: automated policies
// default true, manual policies (evidence_mode: manual) default false.
func defaultOnPush(raw *policySpecRaw) bool {
	if raw.OnPush != nil {
		return *raw.OnPush
	}
	if raw.EvidenceMode == string(core.EvidenceModeManual) {
		return false
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
	if err := validatePolicyEvidenceMode(raw); err != nil {
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
	if raw.EvidenceMode == "" {
		return fmt.Errorf("policy spec %q: missing required field \"evidence_mode\" (want \"automated\" or \"manual\")", raw.ID)
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
	if err := validateCadenceSpec(raw.Cadence); err != nil {
		return fmt.Errorf("policy spec %q: %w", raw.ID, err)
	}
	return nil
}

// validatePolicyEvidenceMode enforces the structural rules for each mode:
//
//   - manual: requires catalog_entry; forbids slots, pass_when, rule
//   - automated: requires slots (≥1) and exactly one of pass_when or rule
func validatePolicyEvidenceMode(raw *policySpecRaw) error {
	switch raw.EvidenceMode {
	case string(core.EvidenceModeManual):
		if raw.CatalogEntry == "" {
			return fmt.Errorf("policy spec %q: evidence_mode \"manual\" requires \"catalog_entry\"", raw.ID)
		}
		if len(raw.Slots) > 0 {
			return fmt.Errorf("policy spec %q: evidence_mode \"manual\" must not declare \"slots\" (manual policies have no configurable slots)", raw.ID)
		}
		if raw.PassWhen.Kind != 0 {
			return fmt.Errorf("policy spec %q: evidence_mode \"manual\" must not declare \"pass_when\" (the universal PDF presence check runs automatically)", raw.ID)
		}
		if raw.Rule != "" {
			return fmt.Errorf("policy spec %q: evidence_mode \"manual\" must not declare \"rule\" (the universal PDF presence check runs automatically)", raw.ID)
		}
	case string(core.EvidenceModeAutomated):
		if err := validatePolicySlots(raw); err != nil {
			return err
		}
		hasPassWhen := raw.PassWhen.Kind != 0
		hasRule := raw.Rule != ""
		if !hasPassWhen && !hasRule {
			return fmt.Errorf("policy spec %q: evidence_mode \"automated\" requires either \"pass_when\" (preferred) or \"rule\" (escape hatch)", raw.ID)
		}
		if hasPassWhen && hasRule {
			return fmt.Errorf("policy spec %q: \"pass_when\" and \"rule\" are mutually exclusive; use \"pass_when\" for declarative logic, \"rule\" only for complex escape-hatch cases", raw.ID)
		}
	default:
		return fmt.Errorf("policy spec %q: invalid evidence_mode %q (want \"automated\" or \"manual\")", raw.ID, raw.EvidenceMode)
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

// parsePassWhen decodes a yaml.Node into a core.PassWhenSpec. The node
// may be a mapping (single-clause) or a sequence (multi-clause).
func parsePassWhen(node *yaml.Node) (*core.PassWhenSpec, error) {
	if node.Kind == yaml.SequenceNode {
		// Multi-slot form: a list of clause mappings.
		clauses := make([]core.PassWhenClause, 0, len(node.Content))
		for i, child := range node.Content {
			clause, err := decodePassWhenClause(child)
			if err != nil {
				return nil, fmt.Errorf("clause[%d]: %w", i, err)
			}
			clauses = append(clauses, clause)
		}
		if len(clauses) == 0 {
			return nil, fmt.Errorf("pass_when list must contain at least one clause")
		}
		return &core.PassWhenSpec{Clauses: clauses}, nil
	}
	if node.Kind == yaml.MappingNode {
		// Single-slot form.
		clause, err := decodePassWhenClause(node)
		if err != nil {
			return nil, err
		}
		return &core.PassWhenSpec{Clauses: []core.PassWhenClause{clause}}, nil
	}
	return nil, fmt.Errorf("pass_when must be a mapping or a sequence of mappings")
}

// decodePassWhenClause decodes one mapping node into a PassWhenClause.
func decodePassWhenClause(node *yaml.Node) (core.PassWhenClause, error) {
	var raw passWhenClauseRaw
	if err := node.Decode(&raw); err != nil {
		return core.PassWhenClause{}, fmt.Errorf("decode clause: %w", err)
	}
	if err := validatePassWhenClause(&raw); err != nil {
		return core.PassWhenClause{}, err
	}
	cond, err := convertCondition(raw.Condition)
	if err != nil {
		return core.PassWhenClause{}, fmt.Errorf("condition: %w", err)
	}
	filter, err := convertCondition(raw.Filter)
	if err != nil {
		return core.PassWhenClause{}, fmt.Errorf("filter: %w", err)
	}
	return core.PassWhenClause{
		Slot:          raw.Slot,
		Quantifier:    core.PassWhenQuantifier(raw.Quantifier),
		Condition:     cond,
		Filter:        filter,
		ViolationMsg:  raw.ViolationMsg,
		IdentityKey:   raw.IdentityKey,
		MinPercentage: raw.MinPercentage,
	}, nil
}

var validPassWhenQuantifiers = map[string]struct{}{
	"all":   {},
	"none":  {},
	"any":   {},
	"count": {},
}

var validPassWhenOps = map[string]struct{}{
	"eq":     {},
	"neq":    {},
	"lt":     {},
	"lte":    {},
	"gt":     {},
	"gte":    {},
	"in":     {},
	"not_in": {},
	"is_set": {},
	"all_of": {},
	"any_of": {},
}

func validatePassWhenClause(raw *passWhenClauseRaw) error {
	if raw.Slot == "" {
		return fmt.Errorf("pass_when clause missing required field \"slot\"")
	}
	if raw.Quantifier == "" {
		return fmt.Errorf("pass_when clause missing required field \"quantifier\"")
	}
	if _, ok := validPassWhenQuantifiers[raw.Quantifier]; !ok {
		return fmt.Errorf("pass_when clause invalid quantifier %q (want all|none|any|count)", raw.Quantifier)
	}
	if raw.Quantifier == "count" && raw.MinPercentage == nil {
		return fmt.Errorf("pass_when clause quantifier \"count\" requires \"min_percentage\"")
	}
	if raw.Quantifier != "count" && raw.MinPercentage != nil {
		return fmt.Errorf("pass_when clause \"min_percentage\" is only valid with quantifier \"count\"")
	}
	if raw.Condition == nil {
		return fmt.Errorf("pass_when clause missing required field \"condition\"")
	}
	return validatePassWhenCondition(raw.Condition)
}

func validatePassWhenCondition(raw *passWhenConditionRaw) error {
	if raw.Op == "" {
		return fmt.Errorf("pass_when condition missing required field \"op\"")
	}
	if _, ok := validPassWhenOps[raw.Op]; !ok {
		return fmt.Errorf("pass_when condition invalid op %q", raw.Op)
	}
	switch raw.Op {
	case "all_of", "any_of":
		if len(raw.Conditions) == 0 {
			return fmt.Errorf("pass_when condition op %q requires at least one sub-condition in \"conditions\"", raw.Op)
		}
		for i, sub := range raw.Conditions {
			if err := validatePassWhenCondition(sub); err != nil {
				return fmt.Errorf("conditions[%d]: %w", i, err)
			}
		}
	default:
		if raw.Field == "" {
			return fmt.Errorf("pass_when condition op %q requires \"field\"", raw.Op)
		}
		if raw.Op != "is_set" && raw.Value == nil {
			return fmt.Errorf("pass_when condition op %q requires \"value\"", raw.Op)
		}
	}
	return nil
}

func convertCondition(raw *passWhenConditionRaw) (*core.PassWhenCondition, error) {
	if raw == nil {
		return nil, nil
	}
	cond := &core.PassWhenCondition{
		Op:    raw.Op,
		Field: raw.Field,
		Value: raw.Value,
	}
	for i, sub := range raw.Conditions {
		converted, err := convertCondition(sub)
		if err != nil {
			return nil, fmt.Errorf("conditions[%d]: %w", i, err)
		}
		cond.Conditions = append(cond.Conditions, converted)
	}
	return cond, nil
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

// everyCadencePrefix duplicates planner.everyCadencePrefix to avoid
// an import cycle (spec → planner). Kept in sync by tests.
const everyCadencePrefix = "every:"

// minEveryDuration mirrors planner.minEveryDuration; see the comment
// there for the rationale.
const minEveryDuration = 5 * time.Minute

// isNamedCadence reports whether c is one of the seven canonical
// named cadences. Power users may also write `every:<duration>`
// (validated separately).
func isNamedCadence(c string) bool {
	_, ok := validCadences[c]
	return ok
}

// validateCadenceSpec accepts either a named cadence (continuous,
// hourly, daily, weekly, monthly, quarterly, annual) or the
// `every:<duration>` form. Duration uses Go's time.ParseDuration
// grammar; values below minEveryDuration are rejected.
func validateCadenceSpec(c string) error {
	if isNamedCadence(c) {
		return nil
	}
	if strings.HasPrefix(c, everyCadencePrefix) {
		raw := strings.TrimPrefix(c, everyCadencePrefix)
		if raw == "" {
			return fmt.Errorf("cadence %q: missing duration after %q", c, everyCadencePrefix)
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("cadence %q: invalid duration: %w", c, err)
		}
		if d <= 0 {
			return fmt.Errorf("cadence %q: duration must be positive", c)
		}
		if d < minEveryDuration {
			return fmt.Errorf("cadence %q: duration %s is below floor %s", c, d, minEveryDuration)
		}
		return nil
	}
	// Best-effort lint hint: a plain duration like "24h" is a common
	// mistake — the user wanted "every:24h" but forgot the prefix.
	if _, err := time.ParseDuration(c); err == nil {
		return fmt.Errorf("invalid cadence %q (did you mean %q? prefix duration cadences with %q)", c, everyCadencePrefix+c, everyCadencePrefix)
	}
	return fmt.Errorf("invalid cadence %q (want continuous|hourly|daily|weekly|monthly|quarterly|annual or every:<duration>)", c)
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
