package planner_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// fakeFramework + fakeSource keep the test self-contained; the real
// loaders are exercised in their own packages.
type fakeFramework struct {
	id, version string
	controls    []core.Control
	policies    []core.PolicyRef
}

func (f *fakeFramework) ID() string                 { return f.id }
func (f *fakeFramework) Version() string            { return f.version }
func (f *fakeFramework) Controls() []core.Control   { return f.controls }
func (f *fakeFramework) Policies() []core.PolicyRef { return f.policies }

type fakeSource struct {
	id    string
	emits []string
}

func (s *fakeSource) ID() string                                 { return s.id }
func (s *fakeSource) Emits() []string                            { return s.emits }
func (s *fakeSource) Init(context.Context, map[string]any) error { return nil }
func (s *fakeSource) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, nil
}

// commitFixture returns a canonical test commit time. Reused across
// tests so the period stays predictable (2026-Q1).
func commitFixture(t *testing.T) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, "2026-02-15T13:55:00Z")
	if err != nil {
		t.Fatalf("time.Parse fixture: %v", err)
	}
	return v
}

func setUp(t *testing.T) *registry.Set {
	t.Helper()
	set := registry.NewSet()
	policy := core.Policy{
		ID:          "soc2.cc6.1.mfa_enforced",
		Control:     "SOC2.CC6.1",
		Description: "MFA",
		Severity:    core.SeverityHigh,
		Cadence:     "daily",
		OnPush:      true,
		RuleRef:     "rules.mfa_enforced.v1",
		Slots: map[string]core.Slot{
			"user_directory": {
				Accepts:     []string{"directory_user"},
				Cardinality: core.SlotOneOrMore,
				Required:    true,
			},
		},
		Parameters: map[string]core.ParameterSpec{
			"exempt_service_accounts": {Type: "bool", Default: true},
		},
	}
	if err := set.Policies.Register(policy); err != nil {
		t.Fatalf("register policy: %v", err)
	}
	fw := &fakeFramework{
		id: "soc2", version: "2017",
		policies: []core.PolicyRef{{PolicyID: policy.ID}},
		controls: []core.Control{{ID: "SOC2.CC6.1", Name: "Logical Access"}},
	}
	if err := set.Frameworks.Register(fw); err != nil {
		t.Fatalf("register framework: %v", err)
	}
	if err := set.Sources.Register(&fakeSource{id: "aws.iam", emits: []string{"directory_user"}}); err != nil {
		t.Fatalf("register aws.iam: %v", err)
	}
	if err := set.Sources.Register(&fakeSource{id: "okta", emits: []string{"directory_user"}}); err != nil {
		t.Fatalf("register okta: %v", err)
	}
	return set
}

func TestPlan_HappyPath(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1",
		Framework:     "soc2",
		Period: spec.PeriodConfig{
			FiscalCalendar: spec.FiscalCalendarConfig{Type: "calendar_quarter"},
		},
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {
				"user_directory": {{Source: "aws.iam"}, {Source: "okta"}},
			},
		},
		PolicyParameters: map[string]map[string]any{
			"soc2.cc6.1.mfa_enforced": {"exempt_service_accounts": false},
		},
		PolicyCadences: map[string]string{
			"soc2.cc6.1.mfa_enforced": "hourly",
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config:     cfg,
		Registries: set,
		CommitTime: commit,
		Now:        commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Period.ID != "2026-Q1" {
		t.Errorf("Period.ID = %q; want 2026-Q1", plan.Period.ID)
	}
	if len(plan.Policies) != 1 {
		t.Fatalf("Policies length = %d; want 1", len(plan.Policies))
	}
	pp := plan.Policies[0]
	if pp.Cadence != "hourly" {
		t.Errorf("Cadence = %q; want hourly", pp.Cadence)
	}
	exempt, ok := pp.Parameters["exempt_service_accounts"].(bool)
	if !ok || exempt {
		t.Errorf("override not applied: %v", pp.Parameters["exempt_service_accounts"])
	}
	bs := pp.Bindings["user_directory"]
	if len(bs) != 2 {
		t.Fatalf("bindings count = %d; want 2", len(bs))
	}
	if bs[0].SourceID != "aws.iam" || bs[1].SourceID != "okta" {
		t.Errorf("binding order/sources mismatched: %+v", bs)
	}
}

func TestPlan_RejectsUnknownSource(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
		Vault: spec.VaultConfig{Backend: "local", Path: "."},
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {
				"user_directory": {{Source: "mystery.source"}},
			},
		},
	}
	_, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: time.Now(), Now: time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "mystery.source") {
		t.Errorf("expected unknown-source error; got %v", err)
	}
}

func TestPlan_RejectsSourceWrongEvidenceType(t *testing.T) {
	set := setUp(t)
	if err := set.Sources.Register(&fakeSource{id: "gcs.storage", emits: []string{"storage_bucket"}}); err != nil {
		t.Fatalf("register gcs.storage: %v", err)
	}
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
		Vault: spec.VaultConfig{Backend: "local", Path: "."},
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {
				"user_directory": {{Source: "gcs.storage"}},
			},
		},
	}
	_, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: time.Now(), Now: time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "none of which is in slot Accepts") {
		t.Errorf("expected slot/source evidence-type mismatch error; got %v", err)
	}
}

func TestPlan_FilterByPolicy(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {"user_directory": {{Source: "aws.iam"}}},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Policies: []string{"nope.no-such-policy"}},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 0 {
		t.Errorf("Policies = %d; want 0 (filter should reject)", len(plan.Policies))
	}
}

func TestPlan_FilterByCadence(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {"user_directory": {{Source: "aws.iam"}}},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Cadence: "daily"},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 1 {
		t.Errorf("cadence=daily should match (policy's cadence is daily); got %d", len(plan.Policies))
	}
	plan, err = planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Cadence: "weekly"},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 0 {
		t.Errorf("cadence=weekly should not match (policy's cadence is daily); got %d", len(plan.Policies))
	}
}

func TestPlan_FilterByCadences_SetIntersection(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {"user_directory": {{Source: "aws.iam"}}},
		},
	}
	commit := commitFixture(t)

	// Policy is cadence=daily + on_push=true (see setUp). Effective cadences = {daily, on_push}.
	cases := []struct {
		name     string
		cadences []string
		want     int
	}{
		{"matches daily via Cadences", []string{"daily"}, 1},
		{"matches on_push via Cadences", []string{core.CadenceOnPush}, 1},
		{"matches when at least one element intersects", []string{"weekly", "daily"}, 1},
		{"no match when set disjoint", []string{"weekly", "monthly"}, 0},
		{"matches on_push even when scheduled-only cadences listed", []string{"weekly", core.CadenceOnPush}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planner.Plan(&planner.Input{
				Config: cfg, Registries: set, CommitTime: commit, Now: commit,
				Filter: planner.Filter{Cadences: tc.cadences},
			})
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			if len(plan.Policies) != tc.want {
				t.Errorf("Cadences=%v: got %d policies; want %d", tc.cadences, len(plan.Policies), tc.want)
			}
		})
	}
}

func TestPlan_FilterByCadences_RespectsOverride(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {"user_directory": {{Source: "aws.iam"}}},
		},
		// Override base cadence from daily → hourly.
		PolicyCadences: map[string]string{"soc2.cc6.1.mfa_enforced": "hourly"},
	}
	commit := commitFixture(t)

	// With the override, {daily} no longer matches but {hourly} does.
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Cadences: []string{"daily"}},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 0 {
		t.Errorf("override should hide daily; got %d policies", len(plan.Policies))
	}
	plan, err = planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Cadences: []string{"hourly"}},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 1 {
		t.Errorf("override should expose hourly; got %d policies", len(plan.Policies))
	}
}

func TestPlan_FilterMutualExclusionEnforced(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
	}
	_, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: time.Now(), Now: time.Now(),
		Filter: planner.Filter{
			Policies: []string{"x"},
			Cadence:  "daily",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual-exclusion error; got %v", err)
	}
}

func TestPlan_ExceptionApplied(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {"user_directory": {{Source: "aws.iam"}}},
		},
		Exceptions: []spec.ExceptionConfig{
			{Policy: "soc2.cc6.1.mfa_enforced", State: "waived", Reason: "Legacy."},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Policies[0].Exception == nil {
		t.Fatal("expected exception applied; got nil")
	}
	if plan.Policies[0].Exception.State != core.StatusWaived {
		t.Errorf("Exception.State = %q; want waived", plan.Policies[0].Exception.State)
	}
}

func TestPlan_ExpiredExceptionSkipped(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: "project.v1", Framework: "soc2",
		Bindings: map[string]map[string][]spec.BindingEntry{
			"soc2.cc6.1.mfa_enforced": {"user_directory": {{Source: "aws.iam"}}},
		},
		Exceptions: []spec.ExceptionConfig{
			{Policy: "soc2.cc6.1.mfa_enforced", State: "waived", Reason: "Expired.", ExpiresAt: "2025-01-01"},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Policies[0].Exception != nil {
		t.Errorf("expired exception should not apply; got %+v", plan.Policies[0].Exception)
	}
}
