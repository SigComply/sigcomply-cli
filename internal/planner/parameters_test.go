package planner

import (
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Parameter names and values reused across the resolveParameters tests.
const (
	paramCutoff     = "cutoff"
	paramMaxAgeDays = "max_age_days"
	paramRegion     = "region"
	paramThreshold  = "threshold"

	regionUSEast1 = "us-east-1"
	regionUSWest2 = "us-west-2"

	cadenceHourly = "hourly"
)

// paramAs is a test helper that fetches a parameter and type-asserts
// it in one step, failing the test with a clear message on either
// missing key or wrong type.
func paramAs[T any](t *testing.T, m map[string]any, key string) T {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("missing parameter %q", key)
	}
	typed, ok := v.(T)
	if !ok {
		var zero T
		t.Fatalf("parameter %q: expected %T, got %T", key, zero, v)
	}
	return typed
}

func makePolicy() *core.Policy {
	return &core.Policy{
		ID: "soc2.cc6.1.access_key_rotation",
		Parameters: map[string]core.ParameterSpec{
			paramMaxAgeDays: {Type: "int", Default: 90, Min: 1, Max: 365},
			"approved_kms_keys": {
				Type:    "list_of_string",
				Default: []any{},
			},
			"enforce_in_grace_period": {Type: "bool", Default: false},
			"retention_window":        {Type: "duration", Default: "30d"},
		},
	}
}

func TestResolveParameters_DefaultsWhenNoOverrides(t *testing.T) {
	p := makePolicy()
	params, err := resolveParameters(p, nil)
	if err != nil {
		t.Fatalf("resolveParameters: %v", err)
	}
	if got := paramAs[int](t, params, paramMaxAgeDays); got != 90 {
		t.Errorf("max_age_days = %v; want 90", got)
	}
	if got := paramAs[bool](t, params, "enforce_in_grace_period"); got {
		t.Errorf("enforce_in_grace_period = %v; want false", got)
	}
	if got := paramAs[time.Duration](t, params, "retention_window"); got != 30*24*time.Hour {
		t.Errorf("retention_window = %v; want 30d", got)
	}
}

func TestResolveParameters_OverridesApplied(t *testing.T) {
	p := makePolicy()
	params, err := resolveParameters(p, map[string]any{
		paramMaxAgeDays:           60,
		"enforce_in_grace_period": true,
	})
	if err != nil {
		t.Fatalf("resolveParameters: %v", err)
	}
	if got := paramAs[int](t, params, paramMaxAgeDays); got != 60 {
		t.Errorf("max_age_days = %v; want 60", got)
	}
	if got := paramAs[bool](t, params, "enforce_in_grace_period"); !got {
		t.Errorf("enforce_in_grace_period = %v; want true", got)
	}
	if got := paramAs[time.Duration](t, params, "retention_window"); got != 30*24*time.Hour {
		t.Errorf("retention_window default lost on partial override: %v", got)
	}
}

func TestResolveParameters_RejectsOutOfBounds(t *testing.T) {
	p := makePolicy()
	_, err := resolveParameters(p, map[string]any{paramMaxAgeDays: 500})
	if err == nil {
		t.Fatal("expected error for out-of-bounds value")
	}
	if !strings.Contains(err.Error(), "above max") {
		t.Errorf("error = %q; want substring \"above max\"", err.Error())
	}
}

func TestResolveParameters_RejectsUnknownOverride(t *testing.T) {
	p := makePolicy()
	_, err := resolveParameters(p, map[string]any{"hypothetical_knob": 7})
	if err == nil {
		t.Fatal("expected error for unknown parameter override")
	}
	if !strings.Contains(err.Error(), "hypothetical_knob") {
		t.Errorf("error = %q; want to name the offending key", err.Error())
	}
}

func TestResolveParameters_StringEnum(t *testing.T) {
	p := &core.Policy{
		ID: "test.string_enum",
		Parameters: map[string]core.ParameterSpec{
			paramRegion: {
				Type:    "string",
				Default: regionUSEast1,
				Enum:    []any{regionUSEast1, regionUSWest2},
			},
		},
	}
	if _, err := resolveParameters(p, map[string]any{paramRegion: "eu-west-1"}); err == nil {
		t.Error("expected enum-violation error")
	}
	if _, err := resolveParameters(p, map[string]any{paramRegion: regionUSWest2}); err != nil {
		t.Errorf("expected enum-match to succeed: %v", err)
	}
}

func TestResolveParameters_DurationParses(t *testing.T) {
	p := &core.Policy{
		ID: "test.dur",
		Parameters: map[string]core.ParameterSpec{
			"window": {Type: "duration", Default: "24h"},
		},
	}
	params, err := resolveParameters(p, map[string]any{"window": "15d"})
	if err != nil {
		t.Fatalf("resolveParameters: %v", err)
	}
	if got := paramAs[time.Duration](t, params, "window"); got != 15*24*time.Hour {
		t.Errorf("window = %v; want 15*24h", got)
	}
}

func TestResolveParameters_Float(t *testing.T) {
	p := &core.Policy{
		ID: "test.float",
		Parameters: map[string]core.ParameterSpec{
			paramThreshold: {Type: "float", Default: 0.95, Min: 0.0, Max: 1.0},
		},
	}
	params, err := resolveParameters(p, map[string]any{paramThreshold: 0.75})
	if err != nil {
		t.Fatalf("resolveParameters: %v", err)
	}
	if got := paramAs[float64](t, params, paramThreshold); got != 0.75 {
		t.Errorf("threshold = %v; want 0.75", got)
	}
	if _, err := resolveParameters(p, map[string]any{paramThreshold: 2.0}); err == nil {
		t.Error("expected above-max error")
	}
	if _, err := resolveParameters(p, map[string]any{paramThreshold: -0.1}); err == nil {
		t.Error("expected below-min error")
	}
}

func TestResolveParameters_Date(t *testing.T) {
	p := &core.Policy{
		ID: "test.date",
		Parameters: map[string]core.ParameterSpec{
			paramCutoff: {Type: "date", Default: "2026-01-01"},
		},
	}
	params, err := resolveParameters(p, map[string]any{paramCutoff: "2026-06-15"})
	if err != nil {
		t.Fatalf("resolveParameters: %v", err)
	}
	got := paramAs[time.Time](t, params, paramCutoff)
	if got.Year() != 2026 || got.Month() != 6 || got.Day() != 15 {
		t.Errorf("cutoff = %v; want 2026-06-15", got)
	}
	if _, err := resolveParameters(p, map[string]any{paramCutoff: "06/15/2026"}); err == nil {
		t.Error("expected error for non-ISO date")
	}
}

func TestResolveParameters_ListOfInt(t *testing.T) {
	p := &core.Policy{
		ID: "test.li",
		Parameters: map[string]core.ParameterSpec{
			"ports": {Type: "list_of_int", Default: []any{80, 443}},
		},
	}
	params, err := resolveParameters(p, map[string]any{"ports": []any{22, 80}})
	if err != nil {
		t.Fatalf("resolveParameters: %v", err)
	}
	got := paramAs[[]int](t, params, "ports")
	if len(got) != 2 || got[0] != 22 || got[1] != 80 {
		t.Errorf("ports = %v; want [22, 80]", got)
	}
}

func TestResolveParameters_ListOfString(t *testing.T) {
	p := &core.Policy{
		ID: "test.ls",
		Parameters: map[string]core.ParameterSpec{
			"regions": {Type: "list_of_string", Default: []any{regionUSEast1}},
		},
	}
	params, err := resolveParameters(p, map[string]any{"regions": []any{regionUSWest2, "eu-west-1"}})
	if err != nil {
		t.Fatalf("resolveParameters: %v", err)
	}
	got := paramAs[[]string](t, params, "regions")
	if len(got) != 2 {
		t.Errorf("regions = %v; want length 2", got)
	}
}

func TestResolveParameters_UnsupportedType(t *testing.T) {
	p := &core.Policy{
		ID: "test.unsup",
		Parameters: map[string]core.ParameterSpec{
			"foo": {Type: "complex_number", Default: nil},
		},
	}
	if _, err := resolveParameters(p, nil); err == nil {
		t.Error("expected error for unsupported parameter type")
	}
}

func TestResolveCadence(t *testing.T) {
	const cadenceDaily = "daily"
	withOverride := &spec.ProjectConfig{Policies: map[string]spec.PolicyConfig{"p1": {Cadence: cadenceHourly}}}
	if c := resolveCadence("p1", cadenceDaily, withOverride); c != cadenceHourly {
		t.Errorf("override not applied: got %q want hourly", c)
	}
	otherPolicy := &spec.ProjectConfig{Policies: map[string]spec.PolicyConfig{"p2": {Cadence: cadenceHourly}}}
	if c := resolveCadence("p1", cadenceDaily, otherPolicy); c != cadenceDaily {
		t.Errorf("default lost: got %q want %s", c, cadenceDaily)
	}
	if c := resolveCadence("p1", cadenceDaily, &spec.ProjectConfig{}); c != cadenceDaily {
		t.Errorf("empty cfg: got %q want %s", c, cadenceDaily)
	}
}
