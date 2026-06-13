package planner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// resolveParameters computes the effective parameter map for a policy:
// the policy spec's defaults overlaid with the project config's
// overrides, then validated against each parameter's type / bounds.
//
// The returned map carries every parameter the policy declares,
// populated (the default when no override is set). Out-of-bounds
// values yield an error — the planner is expected to surface this as
// exit code 3.
func resolveParameters(policy *core.Policy, overrides map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(policy.Parameters))
	for name, spec := range policy.Parameters {
		raw, hasOverride := overrides[name]
		if !hasOverride {
			raw = spec.Default
		}
		validated, err := validateParameter(policy.ID, name, &spec, raw)
		if err != nil {
			return nil, err
		}
		out[name] = validated
	}
	// Any override key that doesn't correspond to a declared parameter
	// is a configuration error — the customer thinks they're tuning a
	// knob that doesn't exist. The CLI should fail loudly.
	for name := range overrides {
		if _, declared := policy.Parameters[name]; !declared {
			return nil, fmt.Errorf("planner: policy %q: parameter override %q does not match any declared parameter", policy.ID, name)
		}
	}
	return out, nil
}

func validateParameter(policyID, name string, pspec *core.ParameterSpec, value any) (any, error) {
	switch pspec.Type {
	case "bool":
		return validateBool(policyID, name, value)
	case "int":
		return validateInt(policyID, name, pspec, value)
	case "float":
		return validateFloat(policyID, name, pspec, value)
	case "string":
		return validateString(policyID, name, pspec, value)
	case "duration":
		return validateDuration(policyID, name, value)
	case "date":
		return validateDate(policyID, name, value)
	case "list_of_string":
		return validateListOfString(policyID, name, value)
	case "list_of_int":
		return validateListOfInt(policyID, name, value)
	default:
		return nil, fmt.Errorf("planner: policy %q: parameter %q has unsupported type %q", policyID, name, pspec.Type)
	}
}

func validateBool(policyID, name string, v any) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("planner: policy %q: parameter %q: expected bool, got %T", policyID, name, v)
	}
	return b, nil
}

func validateInt(policyID, name string, pspec *core.ParameterSpec, v any) (int, error) {
	n, err := toInt(v)
	if err != nil {
		return 0, fmt.Errorf("planner: policy %q: parameter %q: %w", policyID, name, err)
	}
	if pspec.Min != nil {
		minVal, err := toInt(pspec.Min)
		if err == nil && n < minVal {
			return 0, fmt.Errorf("planner: policy %q: parameter %q: value %d below min %d", policyID, name, n, minVal)
		}
	}
	if pspec.Max != nil {
		maxVal, err := toInt(pspec.Max)
		if err == nil && n > maxVal {
			return 0, fmt.Errorf("planner: policy %q: parameter %q: value %d above max %d", policyID, name, n, maxVal)
		}
	}
	return n, nil
}

func validateFloat(policyID, name string, pspec *core.ParameterSpec, v any) (float64, error) {
	f, err := toFloat(v)
	if err != nil {
		return 0, fmt.Errorf("planner: policy %q: parameter %q: %w", policyID, name, err)
	}
	if pspec.Min != nil {
		minVal, err := toFloat(pspec.Min)
		if err == nil && f < minVal {
			return 0, fmt.Errorf("planner: policy %q: parameter %q: value %v below min %v", policyID, name, f, minVal)
		}
	}
	if pspec.Max != nil {
		maxVal, err := toFloat(pspec.Max)
		if err == nil && f > maxVal {
			return 0, fmt.Errorf("planner: policy %q: parameter %q: value %v above max %v", policyID, name, f, maxVal)
		}
	}
	return f, nil
}

func validateString(policyID, name string, pspec *core.ParameterSpec, v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("planner: policy %q: parameter %q: expected string, got %T", policyID, name, v)
	}
	if len(pspec.Enum) > 0 {
		found := false
		for _, allowed := range pspec.Enum {
			if allowedStr, ok := allowed.(string); ok && allowedStr == s {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("planner: policy %q: parameter %q: value %q not in enum %v", policyID, name, s, pspec.Enum)
		}
	}
	if pspec.Pattern != "" {
		re, err := regexp.Compile(pspec.Pattern)
		if err != nil {
			return "", fmt.Errorf("planner: policy %q: parameter %q: invalid pattern %q: %w", policyID, name, pspec.Pattern, err)
		}
		if !re.MatchString(s) {
			return "", fmt.Errorf("planner: policy %q: parameter %q: value %q does not match pattern %q", policyID, name, s, pspec.Pattern)
		}
	}
	return s, nil
}

func validateDuration(policyID, name string, v any) (time.Duration, error) {
	s, ok := v.(string)
	if !ok {
		return 0, fmt.Errorf("planner: policy %q: parameter %q: duration expected as string, got %T", policyID, name, v)
	}
	d, err := parseExtendedDuration(s)
	if err != nil {
		return 0, fmt.Errorf("planner: policy %q: parameter %q: %w", policyID, name, err)
	}
	return d, nil
}

// parseExtendedDuration extends time.ParseDuration with day units
// ("30d" → 30*24h). The standard library refuses "d" because it's
// not a SI unit; the spec lets policies use it because that's how
// humans express retention windows.
func parseExtendedDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func validateDate(policyID, name string, v any) (time.Time, error) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("planner: policy %q: parameter %q: date expected as string, got %T", policyID, name, v)
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("planner: policy %q: parameter %q: %w", policyID, name, err)
	}
	return t, nil
}

func validateListOfString(policyID, name string, v any) ([]string, error) {
	xs, ok := v.([]any)
	if !ok {
		// yaml.v3 may decode list_of_string as []any; tolerate
		// []string as well in case a Go caller passes one directly.
		if direct, okStr := v.([]string); okStr {
			return direct, nil
		}
		return nil, fmt.Errorf("planner: policy %q: parameter %q: expected list, got %T", policyID, name, v)
	}
	out := make([]string, 0, len(xs))
	for i, x := range xs {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("planner: policy %q: parameter %q[%d]: expected string, got %T", policyID, name, i, x)
		}
		out = append(out, s)
	}
	return out, nil
}

func validateListOfInt(policyID, name string, v any) ([]int, error) {
	xs, ok := v.([]any)
	if !ok {
		if direct, okInt := v.([]int); okInt {
			return direct, nil
		}
		return nil, fmt.Errorf("planner: policy %q: parameter %q: expected list, got %T", policyID, name, v)
	}
	out := make([]int, 0, len(xs))
	for i, x := range xs {
		n, err := toInt(x)
		if err != nil {
			return nil, fmt.Errorf("planner: policy %q: parameter %q[%d]: %w", policyID, name, i, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		// YAML may decode "90" as float64 when in a context expecting any.
		if n != float64(int(n)) {
			return 0, fmt.Errorf("expected int, got non-integer %v", n)
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("expected int, got %T", v)
	}
}

func toFloat(v any) (float64, error) {
	switch f := v.(type) {
	case float64:
		return f, nil
	case int:
		return float64(f), nil
	case int64:
		return float64(f), nil
	default:
		return 0, fmt.Errorf("expected float, got %T", v)
	}
}

// resolveCadence returns the effective cadence: the project override from
// policies[policyID].cadence if present, otherwise the policy's declared
// cadence.
func resolveCadence(policyID, policyCadence string, cfg *spec.ProjectConfig) string {
	if c := cfg.CadenceFor(policyID); c != "" {
		return c
	}
	return policyCadence
}
