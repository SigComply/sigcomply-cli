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
		if !evalCondition(clause.Condition, rec, params) {
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
		if evalCondition(clause.Condition, rec, params) {
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
		if evalCondition(clause.Condition, &records[i], params) {
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
		if evalCondition(clause.Condition, &records[i], params) {
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

// filterRecords returns the subset of records that satisfy the filter condition.
func filterRecords(records []core.EvidenceRecord, filter *core.PassWhenCondition, params map[string]any) []core.EvidenceRecord {
	out := make([]core.EvidenceRecord, 0, len(records))
	for i := range records {
		if evalCondition(filter, &records[i], params) {
			out = append(out, records[i])
		}
	}
	return out
}

// evalCondition evaluates a single PassWhenCondition against a record.
func evalCondition(cond *core.PassWhenCondition, rec *core.EvidenceRecord, params map[string]any) bool {
	switch cond.Op {
	case "all_of":
		for _, sub := range cond.Conditions {
			if !evalCondition(sub, rec, params) {
				return false
			}
		}
		return true
	case "any_of":
		for _, sub := range cond.Conditions {
			if evalCondition(sub, rec, params) {
				return true
			}
		}
		return false
	case "is_set":
		v, ok := getField(rec, cond.Field)
		return ok && v != nil
	}

	lhs, _ := getField(rec, cond.Field)
	rhs := resolveValue(cond.Value, params)

	return evalComparisonOp(cond.Op, lhs, rhs)
}

// evalComparisonOp dispatches binary comparison operators.
func evalComparisonOp(op string, lhs, rhs any) bool {
	switch op {
	case "eq":
		return deepEqual(lhs, rhs)
	case "neq":
		return !deepEqual(lhs, rhs)
	case "lt":
		return compareNumeric(lhs, rhs) < 0
	case "lte":
		return compareNumeric(lhs, rhs) <= 0
	case "gt":
		return compareNumeric(lhs, rhs) > 0
	case "gte":
		return compareNumeric(lhs, rhs) >= 0
	case "in":
		return containsValue(lhs, rhs)
	case "not_in":
		return !containsValue(lhs, rhs)
	}
	return false
}

// getField navigates a dot-path to extract a value from an EvidenceRecord.
// Supported paths:
//   - "id", "type", "source_id" — top-level record fields
//   - "payload.<key>.<...>" — dot-path into the JSON payload
//   - "$params.<name>" — policy effective parameter (handled by resolveValue;
//     getField returns ok=false for $params paths so callers handle them via rhs)
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
func deepEqual(a, b any) bool {
	af := toFloat64(a)
	bf := toFloat64(b)
	if af != nil && bf != nil {
		return *af == *bf
	}
	// Non-numeric: fall back to string comparison for booleans and strings.
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

// compareNumeric returns -1, 0, or 1 for numeric comparisons.
// Returns 0 on non-numeric inputs (condition will produce false for lt/gt).
func compareNumeric(a, b any) int {
	af := toFloat64(a)
	bf := toFloat64(b)
	if af == nil || bf == nil {
		return 0
	}
	switch {
	case *af < *bf:
		return -1
	case *af > *bf:
		return 1
	default:
		return 0
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
