package planner_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// minimalPolicyYAML builds a valid policy document with the given cadence
// so LoadPolicy's cadence validation is the only variable under test.
func minimalPolicyYAML(cadence string) []byte {
	return []byte(fmt.Sprintf(`schema_version: policy.v1
id: test.policy
control: SOC2.CC6.1
severity: high
category: access
cadence: %q
evidence_mode: automated
description: test
remediation: test
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
    description: x
pass_when:
  slot: s
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`, cadence))
}

// TestCadenceValidation_SpecMatchesPlanner guards the deliberate
// duplication of cadence vocabulary between the spec and planner packages
// (kept apart to avoid a planner→spec import cycle). It drives a battery
// of cadence strings — including the 5-minute floor — through both
// spec.LoadPolicy and planner.ValidateCadence and asserts they agree on
// accept/reject.
func TestCadenceValidation_SpecMatchesPlanner(t *testing.T) {
	inputs := []string{
		"continuous", "hourly", "daily", "weekly", "monthly", "quarterly", "annual",
		"every:5m", "every:6h", "every:2h30m", "every:24h",
		"every:1m", "every:0s", "every:-1h", "every:", "every:abc",
		"24h", "yearly", "biweekly",
	}
	for _, in := range inputs {
		_, specErr := spec.LoadPolicy(minimalPolicyYAML(in))
		specRejected := specErr != nil && strings.Contains(strings.ToLower(specErr.Error()), "cadence")
		// LoadPolicy may fail for a reason other than cadence; only treat a
		// cadence-mentioning error as a cadence rejection.
		if specErr != nil && !specRejected {
			t.Fatalf("cadence %q: LoadPolicy failed for a non-cadence reason: %v", in, specErr)
		}
		plannerRejected := planner.ValidateCadence(in) != nil
		if specRejected != plannerRejected {
			t.Errorf("cadence %q: spec rejects=%v but planner rejects=%v (validators out of sync)", in, specRejected, plannerRejected)
		}
	}
}

// TestCadenceInterval_EveryForms covers the every:<duration> → interval
// mapping and the 5-minute floor degradation — the string→interval path
// the whole every:* feature depends on, previously asserted nowhere.
func TestCadenceInterval_EveryForms(t *testing.T) {
	cases := []struct {
		cadence string
		want    time.Duration
	}{
		{"every:6h", 6 * time.Hour},
		{"every:2h30m", 2*time.Hour + 30*time.Minute},
		{"every:5m", 5 * time.Minute},
		{"every:1m", 0},   // below floor → 0 (always due)
		{"every:abc", 0},  // unparseable → 0 (loud, always due)
		{"continuous", 0}, // always due
		{"hourly", 0},     // sub-daily named cadence → always due
	}
	for _, c := range cases {
		if got := planner.CadenceInterval(c.cadence); got != c.want {
			t.Errorf("CadenceInterval(%q) = %v; want %v", c.cadence, got, c.want)
		}
	}
}

// TestNextDueAt_EveryAndContinuous covers NextDueAt's zero-time cases and
// the exact every:<duration> add.
func TestNextDueAt_EveryAndContinuous(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if got := planner.NextDueAt("continuous", base); !got.IsZero() {
		t.Errorf("NextDueAt(continuous) = %v; want zero (always due)", got)
	}
	if got := planner.NextDueAt("daily", time.Time{}); !got.IsZero() {
		t.Errorf("NextDueAt with zero lastPass = %v; want zero", got)
	}
	if got := planner.NextDueAt("every:6h", base); !got.Equal(base.Add(6 * time.Hour)) {
		t.Errorf("NextDueAt(every:6h) = %v; want %v", got, base.Add(6*time.Hour))
	}
}

// TestIsDue covers the authoritative per-policy gating layers: first-run,
// on_fail_retry (any prior non-pass forces due), and the cadence-elapsed
// boundary. This is the load-bearing logic of the two-axis cadence
// invariant and was previously exercised by no direct test.
func TestIsDue(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	dailyInterval := planner.CadenceInterval("daily") // 23h with cron slack

	cases := []struct {
		name    string
		cadence string
		state   *core.PolicyState
		want    bool
	}{
		{"nil state is first-run → due", "daily", nil, true},
		{"zero LastRunAt is first-run → due", "daily", &core.PolicyState{}, true},
		{
			"prior fail forces due regardless of cadence",
			"annual",
			&core.PolicyState{LastRunAt: now.Add(-time.Hour), LastRunStatus: core.StatusFail, LastPassAt: now.Add(-time.Hour)},
			true,
		},
		{
			"prior error forces due",
			"annual",
			&core.PolicyState{LastRunAt: now.Add(-time.Hour), LastRunStatus: core.StatusError},
			true,
		},
		{
			"passed within interval → not due",
			"daily",
			&core.PolicyState{LastRunAt: now.Add(-time.Hour), LastRunStatus: core.StatusPass, LastPassAt: now.Add(-time.Hour)},
			false,
		},
		{
			"passed exactly interval ago → due (>=)",
			"daily",
			&core.PolicyState{LastRunAt: now.Add(-dailyInterval), LastRunStatus: core.StatusPass, LastPassAt: now.Add(-dailyInterval)},
			true,
		},
		{
			"passed just under interval → not due",
			"daily",
			&core.PolicyState{LastRunAt: now, LastRunStatus: core.StatusPass, LastPassAt: now.Add(-dailyInterval + time.Minute)},
			false,
		},
		{
			"continuous cadence is always due even right after a pass",
			"continuous",
			&core.PolicyState{LastRunAt: now, LastRunStatus: core.StatusPass, LastPassAt: now},
			true,
		},
	}
	for _, c := range cases {
		if got := planner.IsDue(c.cadence, c.state, now); got != c.want {
			t.Errorf("%s: IsDue = %v; want %v", c.name, got, c.want)
		}
	}
}
