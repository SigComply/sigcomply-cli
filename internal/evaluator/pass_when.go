package evaluator

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// evaluatePassWhen implements Path B: the pass_when: declarative DSL for
// evidence_mode: automated policies. Each clause in the spec is evaluated
// independently; the policy passes iff all clauses pass.
func evaluatePassWhen(spec *core.PassWhenSpec, slots map[string][]core.EvidenceRecord, params map[string]any) core.RuleResult {
	var allViolations []core.Violation
	for i := range spec.Clauses {
		clause := &spec.Clauses[i]
		result := evaluatePassWhenClause(clause, slots[clause.Slot], params)
		if result.Status == core.StatusError {
			return result
		}
		allViolations = append(allViolations, result.Violations...)
	}
	if len(allViolations) > 0 {
		return core.RuleResult{Status: core.StatusFail, Violations: allViolations}
	}
	return core.RuleResult{Status: core.StatusPass}
}

// evaluatePassWhenClause evaluates one clause against its slot's records.
func evaluatePassWhenClause(clause *core.PassWhenClause, records []core.EvidenceRecord, params map[string]any) core.RuleResult {
	// Pre-filter: exclude records that do not satisfy the filter condition.
	included := records
	if clause.Filter != nil {
		included = filterRecords(records, clause.Filter, params)
	}

	identityKey := clause.IdentityKey
	if identityKey == "" {
		identityKey = "id"
	}

	switch clause.Quantifier {
	case core.QuantifierAll:
		return evaluateAll(clause, included, params, identityKey)
	case core.QuantifierNone:
		return evaluateNone(clause, included, params, identityKey)
	case core.QuantifierAny:
		return evaluateAny(clause, included, params)
	case core.QuantifierCount:
		return evaluateCount(clause, included, params)
	default:
		return core.RuleResult{
			Status: core.StatusError,
			Diag:   map[string]any{"reason": fmt.Sprintf("pass_when: unknown quantifier %q", clause.Quantifier)},
		}
	}
}

// evaluateAll: policy passes iff every included record satisfies the condition.
func evaluateAll(clause *core.PassWhenClause, records []core.EvidenceRecord, params map[string]any, identityKey string) core.RuleResult {
	var violations []core.Violation
	seen := map[string]struct{}{}
	for i := range records {
		rec := &records[i]
		ok, err := evalCondition(clause.Condition, rec, params)
		if err != nil {
			return conditionErr(err)
		}
		if !ok {
			key := recordIdentity(rec, identityKey)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			violations = append(violations, core.Violation{
				ResourceID: key,
				Reason:     renderMsg(clause.ViolationMsg, rec),
			})
		}
	}
	if len(violations) > 0 {
		return core.RuleResult{Status: core.StatusFail, Violations: violations}
	}
	return core.RuleResult{Status: core.StatusPass}
}

// evaluateNone: policy passes iff no included record satisfies the condition.
func evaluateNone(clause *core.PassWhenClause, records []core.EvidenceRecord, params map[string]any, identityKey string) core.RuleResult {
	var violations []core.Violation
	seen := map[string]struct{}{}
	for i := range records {
		rec := &records[i]
		ok, err := evalCondition(clause.Condition, rec, params)
		if err != nil {
			return conditionErr(err)
		}
		if ok {
			key := recordIdentity(rec, identityKey)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			violations = append(violations, core.Violation{
				ResourceID: key,
				Reason:     renderMsg(clause.ViolationMsg, rec),
			})
		}
	}
	if len(violations) > 0 {
		return core.RuleResult{Status: core.StatusFail, Violations: violations}
	}
	return core.RuleResult{Status: core.StatusPass}
}

// evaluateAny: policy passes iff at least one included record satisfies the condition.
func evaluateAny(clause *core.PassWhenClause, records []core.EvidenceRecord, params map[string]any) core.RuleResult {
	if len(records) == 0 {
		return core.RuleResult{
			Status: core.StatusFail,
			Violations: []core.Violation{
				{Reason: renderMsg(clause.ViolationMsg, nil)},
			},
		}
	}
	for i := range records {
		ok, err := evalCondition(clause.Condition, &records[i], params)
		if err != nil {
			return conditionErr(err)
		}
		if ok {
			return core.RuleResult{Status: core.StatusPass}
		}
	}
	return core.RuleResult{
		Status: core.StatusFail,
		Violations: []core.Violation{
			{Reason: fmt.Sprintf("no record in slot %q satisfied the condition", clause.Slot)},
		},
	}
}

// evaluateCount: policy passes iff at least MinPercentage% of records satisfy the condition.
func evaluateCount(clause *core.PassWhenClause, records []core.EvidenceRecord, params map[string]any) core.RuleResult {
	if len(records) == 0 {
		// 0 records: 0% pass, which fails any min_percentage > 0.
		if clause.MinPercentage != nil && *clause.MinPercentage > 0 {
			return core.RuleResult{
				Status:     core.StatusFail,
				Violations: []core.Violation{{Reason: "no records to evaluate"}},
			}
		}
		return core.RuleResult{Status: core.StatusPass}
	}
	passing := 0
	for i := range records {
		ok, err := evalCondition(clause.Condition, &records[i], params)
		if err != nil {
			return conditionErr(err)
		}
		if ok {
			passing++
		}
	}
	pct := float64(passing) / float64(len(records)) * 100
	minPct := 0.0
	if clause.MinPercentage != nil {
		minPct = *clause.MinPercentage
	}
	if pct < minPct {
		return core.RuleResult{
			Status: core.StatusFail,
			Violations: []core.Violation{{
				Reason: fmt.Sprintf("only %.1f%% of records passed (%.0f%% required)", pct, minPct),
			}},
		}
	}
	return core.RuleResult{Status: core.StatusPass}
}

// conditionErr wraps a condition-evaluation error as a policy-level
// error result. A missing field is a contract gap (the evidence type
// does not carry a fact the policy asks about), never a pass or fail.
func conditionErr(err error) core.RuleResult {
	return core.RuleResult{
		Status: core.StatusError,
		Diag:   map[string]any{"reason": err.Error()},
	}
}

// filterRecords returns the subset of records that satisfy the filter
// condition. Filters are lenient: a record whose filter field is absent
// (or whose filter evaluation errors) is simply excluded from the set,
// rather than erroring the whole policy — filtering is about scoping the
// records to judge, and "field not present" means "out of scope".
func filterRecords(records []core.EvidenceRecord, filter *core.PassWhenCondition, params map[string]any) []core.EvidenceRecord {
	out := make([]core.EvidenceRecord, 0, len(records))
	for i := range records {
		if ok, err := evalCondition(filter, &records[i], params); err == nil && ok {
			out = append(out, records[i])
		}
	}
	return out
}

// evalCondition evaluates a single PassWhenCondition against a record.
//
// A comparison (eq/neq/lt/lte/gt/gte/in/not_in) whose field is absent
// from the record returns an error: comparing against a fact the
// evidence does not carry is never a meaningful pass or fail, so the
// policy surfaces status=error rather than silently treating the absence
// as a violation (or a vacuous pass). Policies that legitimately tolerate
// an absent field must guard it with the is_set operator (which returns
// false, never errors) or scope it away in a clause filter.
func evalCondition(cond *core.PassWhenCondition, rec *core.EvidenceRecord, params map[string]any) (bool, error) {
	switch cond.Op {
	case "all_of":
		for _, sub := range cond.Conditions {
			ok, err := evalCondition(sub, rec, params)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case "any_of":
		for _, sub := range cond.Conditions {
			ok, err := evalCondition(sub, rec, params)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case "is_set":
		v, ok := getField(rec, cond.Field)
		return ok && v != nil, nil
	}

	lhs, ok := getField(rec, cond.Field)
	if !ok {
		return false, fmt.Errorf(
			"policy references field %q which is not present on record %q (type %q) — "+
				"reference a field the evidence type guarantees, or guard it with is_set/filter",
			cond.Field, rec.ID, rec.Type)
	}
	rhs := resolveValue(cond.Value, params)
	return evalComparisonOp(cond.Op, lhs, rhs)
}

// evalComparisonOp dispatches binary comparison operators. The ordered
// operators (lt/lte/gt/gte) return an error when either operand is
// non-numeric: comparing a string field with < is a policy/evidence
// mismatch that must surface as status=error, never silently evaluate
// to true (the old behavior collapsed non-numerics to 0, so gte/lte
// returned true for any string field — a silent false-pass).
func evalComparisonOp(op string, lhs, rhs any) (bool, error) {
	switch op {
	case "eq":
		return deepEqual(lhs, rhs), nil
	case "neq":
		return !deepEqual(lhs, rhs), nil
	case "lt", "lte", "gt", "gte":
		cmp, ok := compareNumeric(lhs, rhs)
		if !ok {
			return false, fmt.Errorf("operator %q requires numeric operands, got %T and %T", op, lhs, rhs)
		}
		switch op {
		case "lt":
			return cmp < 0, nil
		case "lte":
			return cmp <= 0, nil
		case "gt":
			return cmp > 0, nil
		default: // gte
			return cmp >= 0, nil
		}
	case "in":
		return containsValue(lhs, rhs), nil
	case "not_in":
		return !containsValue(lhs, rhs), nil
	}
	return false, fmt.Errorf("unknown comparison operator %q", op)
}

// getField navigates a dot-path to extract a value from an EvidenceRecord.
// Supported paths:
//   - "id", "type", "source_id" — top-level record fields
//   - "payload.<key>.<...>" — dot-path into the JSON payload
//
// $params.<name> is NOT resolved here: parameters are only valid on the
// Value (RHS) side of a condition, where resolveValue expands them. A
// "$params.*" Field would fall through to the not-found path and error.
func getField(rec *core.EvidenceRecord, path string) (any, bool) {
	if rec == nil {
		return nil, false
	}
	switch path {
	case "id":
		return rec.ID, true
	case "type":
		return rec.Type, true
	case "source_id":
		return rec.SourceID, true
	}
	if strings.HasPrefix(path, "payload.") {
		return getPayloadField(rec.Payload, strings.TrimPrefix(path, "payload."))
	}
	return nil, false
}

// getPayloadField parses the JSON payload and navigates a dot-path.
func getPayloadField(payload json.RawMessage, path string) (any, bool) {
	if len(payload) == 0 {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, false
	}
	return navigateMap(m, strings.Split(path, "."))
}

func navigateMap(m map[string]any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return nil, false
	}
	v, ok := m[parts[0]]
	if !ok {
		return nil, false
	}
	if len(parts) == 1 {
		return v, true
	}
	nested, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	return navigateMap(nested, parts[1:])
}

// resolveValue expands "$params.<name>" references to the actual parameter value.
func resolveValue(v any, params map[string]any) any {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, "$params.") {
		return v
	}
	key := strings.TrimPrefix(s, "$params.")
	if pv, ok := params[key]; ok {
		return pv
	}
	return v
}

// deepEqual compares two values with type coercion for JSON numeric types.
// JSON unmarshalling produces float64 for all numbers; policy YAML produces
// int or float64. We normalise both sides to float64 before comparing.
//
// If exactly one side is numeric, the values are NOT equal: a string
// field "5" must not match the number 5 (JSON types are distinct, and
// evidence types are schema-validated, so a type mismatch is a real
// difference, not an equality). The string fallback applies only when
// neither side is numeric (booleans, strings).
func deepEqual(a, b any) bool {
	af := toFloat64(a)
	bf := toFloat64(b)
	if af != nil && bf != nil {
		return *af == *bf
	}
	if af != nil || bf != nil {
		// Exactly one numeric — different JSON types, never equal.
		return false
	}
	// Neither numeric: compare booleans and strings by string form.
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func toFloat64(v any) *float64 {
	switch x := v.(type) {
	case float64:
		return &x
	case float32:
		f := float64(x)
		return &f
	case int:
		f := float64(x)
		return &f
	case int64:
		f := float64(x)
		return &f
	case int32:
		f := float64(x)
		return &f
	}
	return nil
}

// compareNumeric returns (-1|0|1, true) for numeric comparisons, or
// (0, false) when either input is non-numeric. Callers must treat
// ok=false as "incomparable" and surface an error rather than defaulting
// to a comparison result.
func compareNumeric(a, b any) (int, bool) {
	af := toFloat64(a)
	bf := toFloat64(b)
	if af == nil || bf == nil {
		return 0, false
	}
	switch {
	case *af < *bf:
		return -1, true
	case *af > *bf:
		return 1, true
	default:
		return 0, true
	}
}

// containsValue checks whether lhs appears in rhs (which must be a
// []interface{} for in/not_in semantics). Each element of rhs is compared
// with deepEqual.
func containsValue(lhs, rhs any) bool {
	list, ok := rhs.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if deepEqual(lhs, item) {
			return true
		}
	}
	return false
}

// recordIdentity returns the value of the identityKey field, falling back
// to rec.ID when the field is absent or empty.
func recordIdentity(rec *core.EvidenceRecord, identityKey string) string {
	if identityKey == "id" || identityKey == "" {
		return rec.ID
	}
	v, ok := getField(rec, identityKey)
	if !ok || v == nil {
		return rec.ID
	}
	return fmt.Sprint(v)
}

// templateVar matches {{.field.path}} substitution tokens in violation messages.
var templateVar = regexp.MustCompile(`\{\{\.([^}]+)\}\}`)

// renderMsg executes a violation_message template against the record context.
// rec may be nil (e.g. for any/count failures with no specific record).
func renderMsg(tmpl string, rec *core.EvidenceRecord) string {
	if tmpl == "" || rec == nil {
		return tmpl
	}
	// Build a flat context map: top-level fields + decoded payload fields.
	ctx := map[string]any{
		"id":        rec.ID,
		"type":      rec.Type,
		"source_id": rec.SourceID,
	}
	if len(rec.Payload) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(rec.Payload, &payload); err == nil {
			ctx["payload"] = payload
		}
	}
	return templateVar.ReplaceAllStringFunc(tmpl, func(match string) string {
		path := match[3 : len(match)-2] // strip {{ . and }}
		val, ok := navigateContext(ctx, strings.Split(path, "."))
		if !ok {
			return match // leave unresolved tokens as-is
		}
		return fmt.Sprint(val)
	})
}

func navigateContext(ctx map[string]any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return nil, false
	}
	v, ok := ctx[parts[0]]
	if !ok {
		return nil, false
	}
	if len(parts) == 1 {
		return v, true
	}
	nested, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	return navigateMap(nested, parts[1:])
}
