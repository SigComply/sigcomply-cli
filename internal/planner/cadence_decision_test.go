package planner_test

import (
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// ---- DueReason: deterministic human-readable strings, no identifiers ----
// (IsDue itself is covered by cadence_sync_test.go::TestIsDue.)

func TestDueReason_AllBranches(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		cadence string
		state   *core.PolicyState
		want    string // substring
	}{
		{"first run", "daily", nil, "first run"},
		{"zero state first run", "daily", &core.PolicyState{}, "first run"},
		{
			"prior non-pass", "daily",
			&core.PolicyState{LastRunAt: now.Add(-time.Hour), LastRunStatus: core.StatusFail},
			"on_fail_retry",
		},
		{
			"zero interval cadence", "hourly",
			&core.PolicyState{LastRunAt: now.Add(-time.Hour), LastRunStatus: core.StatusPass, LastPassAt: now.Add(-time.Hour)},
			"always due",
		},
		{
			"interval elapsed", "daily",
			&core.PolicyState{LastRunAt: now.Add(-48 * time.Hour), LastRunStatus: core.StatusPass, LastPassAt: now.Add(-48 * time.Hour)},
			"exceeds cadence interval",
		},
		{
			"not yet due", "daily",
			&core.PolicyState{LastRunAt: now.Add(-time.Hour), LastRunStatus: core.StatusPass, LastPassAt: now.Add(-time.Hour)},
			"not yet elapsed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := planner.DueReason(tc.cadence, tc.state, now)
			if got == "" {
				t.Fatalf("empty reason")
			}
			if !substr(got, tc.want) {
				t.Errorf("DueReason = %q; want substring %q", got, tc.want)
			}
		})
	}
}

// ---- NextDueAt ----

func TestNextDueAt(t *testing.T) {
	lastPass := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	// Never-run → zero.
	if got := planner.NextDueAt("daily", time.Time{}); !got.IsZero() {
		t.Errorf("NextDueAt(zero lastPass) = %v; want zero", got)
	}
	// Continuous (interval 0) → zero.
	if got := planner.NextDueAt("continuous", lastPass); !got.IsZero() {
		t.Errorf("NextDueAt(continuous) = %v; want zero", got)
	}
	// Daily → lastPass + 23h.
	want := lastPass.Add(23 * time.Hour).UTC()
	if got := planner.NextDueAt("daily", lastPass); !got.Equal(want) {
		t.Errorf("NextDueAt(daily) = %v; want %v", got, want)
	}
	// every:6h → exact duration, no slack.
	want = lastPass.Add(6 * time.Hour).UTC()
	if got := planner.NextDueAt("every:6h", lastPass); !got.Equal(want) {
		t.Errorf("NextDueAt(every:6h) = %v; want %v", got, want)
	}
}

// ---- decideEvaluation exercised through Plan with PolicyStates ----

// Plan with a non-nil PolicyStates map enables cadence gating. A policy
// whose prior pass is recent (within the cadence interval) and whose
// content hash is unchanged must carry forward (ShouldEvaluate=false).
func TestPlan_CadenceGate_CarriesForwardWhenNotDue(t *testing.T) {
	set := setUp(t)
	commit := commitFixture(t)
	cfg := minimalPlanConfig()

	// Build the plan once WITHOUT states to learn the policy's content hash.
	bootstrap, err := planner.Plan(&planner.Input{Config: cfg, Registries: set, CommitTime: commit, Now: commit})
	if err != nil {
		t.Fatalf("bootstrap Plan: %v", err)
	}
	hash := bootstrap.Policies[0].ContentHash
	pid := bootstrap.Policies[0].Spec.ID

	// The policy cadence is daily; pretend it passed 1h before "now" with
	// the same content hash. Cadence not elapsed → carry forward.
	now := commit
	states := map[string]*core.PolicyState{
		pid: {
			Framework:      "soc2",
			PolicyID:       pid,
			LastRunAt:      now.Add(-1 * time.Hour),
			LastPassAt:     now.Add(-1 * time.Hour),
			LastRunStatus:  core.StatusPass,
			LastPolicyHash: hash,
		},
	}
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: now,
		PolicyStates: states,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	pp := plan.Policies[0]
	if pp.ShouldEvaluate {
		t.Errorf("ShouldEvaluate = true; want false (cadence not elapsed, hash unchanged)")
	}
	if pp.SkipReason == "" {
		t.Errorf("expected a SkipReason explaining the carry-forward")
	}
}

// A content-hash mismatch forces re-evaluation even when the cadence has
// not elapsed — a bundle/schema change invalidates the prior evaluation.
func TestPlan_CadenceGate_ContentHashMismatchForcesEvaluate(t *testing.T) {
	set := setUp(t)
	commit := commitFixture(t)
	cfg := minimalPlanConfig()

	bootstrap := mustPlan(t, &planner.Input{Config: cfg, Registries: set, CommitTime: commit, Now: commit})
	pid := bootstrap.Policies[0].Spec.ID

	now := commit
	states := map[string]*core.PolicyState{
		pid: {
			Framework:      "soc2",
			PolicyID:       pid,
			LastRunAt:      now.Add(-1 * time.Hour),
			LastPassAt:     now.Add(-1 * time.Hour),
			LastRunStatus:  core.StatusPass,
			LastPolicyHash: "sha256:STALE-DIFFERENT-HASH",
		},
	}
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: now,
		PolicyStates: states,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.Policies[0].ShouldEvaluate {
		t.Errorf("ShouldEvaluate = false; want true (content hash mismatch)")
	}
	if plan.Policies[0].SkipReason == "" {
		t.Errorf("a hash-mismatch re-evaluate should still record an explanatory SkipReason")
	}
}

// An explicit operator filter forces evaluation regardless of cadence
// state — the operator said "run these now."
func TestPlan_ExplicitFilterBypassesCadenceGate(t *testing.T) {
	set := setUp(t)
	commit := commitFixture(t)
	cfg := minimalPlanConfig()

	bootstrap := mustPlan(t, &planner.Input{Config: cfg, Registries: set, CommitTime: commit, Now: commit})
	pid := bootstrap.Policies[0].Spec.ID

	now := commit
	states := map[string]*core.PolicyState{
		pid: {
			Framework: "soc2", PolicyID: pid,
			LastRunAt:      now.Add(-1 * time.Minute),
			LastPassAt:     now.Add(-1 * time.Minute),
			LastRunStatus:  core.StatusPass,
			LastPolicyHash: bootstrap.Policies[0].ContentHash,
		},
	}
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: now,
		PolicyStates: states,
		Filter:       planner.Filter{Policies: []string{pid}},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.Policies[0].ShouldEvaluate {
		t.Errorf("ShouldEvaluate = false; want true (explicit filter overrides cadence)")
	}
}

// A prior FAIL forces re-evaluation through on_fail_retry even when the
// cadence has not elapsed.
func TestPlan_CadenceGate_PriorFailForcesEvaluate(t *testing.T) {
	set := setUp(t)
	commit := commitFixture(t)
	cfg := minimalPlanConfig()

	bootstrap := mustPlan(t, &planner.Input{Config: cfg, Registries: set, CommitTime: commit, Now: commit})
	pid := bootstrap.Policies[0].Spec.ID

	now := commit
	states := map[string]*core.PolicyState{
		pid: {
			Framework: "soc2", PolicyID: pid,
			LastRunAt:      now.Add(-1 * time.Minute),
			LastRunStatus:  core.StatusFail,
			LastPolicyHash: bootstrap.Policies[0].ContentHash,
		},
	}
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: now,
		PolicyStates: states,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.Policies[0].ShouldEvaluate {
		t.Errorf("ShouldEvaluate = false; want true (prior FAIL → on_fail_retry)")
	}
}

// minimalPlanConfig binds the single setUp() policy so the plan is
// well-formed and reaches the cadence gate.
func minimalPlanConfig() *spec.ProjectConfig {
	return &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {"user_directory": {{Source: "aws.iam"}}},
		},
	}
}

// mustPlan runs planner.Plan and fails the test on error.
func mustPlan(t *testing.T, in *planner.Input) *planner.RunPlan {
	t.Helper()
	plan, err := planner.Plan(in)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return plan
}

func substr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
