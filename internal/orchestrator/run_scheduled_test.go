package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
)

// schedSource emits one passing directory_user record.
type schedSource struct{ calls int }

func (*schedSource) ID() string      { return "aws.iam" }
func (*schedSource) Emits() []string { return []string{"directory_user"} }
func (*schedSource) Init(context.Context, map[string]any) error {
	return nil
}
func (s *schedSource) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	s.calls++
	payload, err := json.Marshal(map[string]any{"mfa_enabled": true})
	if err != nil {
		return nil, err
	}
	return []core.EvidenceRecord{
		{Type: "directory_user", ID: "u1", SourceID: "aws.iam", Payload: payload},
	}, nil
}

// schedFramework ships one daily pass_when policy.
type schedFramework struct{}

func (*schedFramework) ID() string      { return testFramework }
func (*schedFramework) Version() string { return "v0" }
func (*schedFramework) Controls() []core.Control {
	return []core.Control{{ID: "SOC2.CC6.1", Name: "Logical Access"}}
}
func (*schedFramework) Policies() []core.PolicyRef {
	return []core.PolicyRef{{PolicyID: "soc2.cc6.1.mfa"}}
}

func schedPolicy() core.Policy {
	return core.Policy{
		ID:           "soc2.cc6.1.mfa",
		Controls:     []core.ControlRef{{ControlID: "SOC2.CC6.1"}},
		Severity:     core.SeverityHigh,
		Cadence:      "daily",
		EvidenceMode: core.EvidenceModeAutomated,
		Slots: map[string]core.Slot{
			"users": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true},
		},
		PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
			Slot:       "users",
			Quantifier: core.QuantifierAll,
			Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.mfa_enabled", Value: true},
		}}},
	}
}

func schedRegistries(t *testing.T, src *schedSource) *registry.Set {
	t.Helper()
	regs := registry.NewSet()
	if err := regs.EvidenceTypes.Register(core.EvidenceType{
		ID: "directory_user", Version: 1,
		Schema: json.RawMessage(`{"type":"object","properties":{"mfa_enabled":{"type":"boolean"}}}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := regs.Frameworks.Register(&schedFramework{}); err != nil {
		t.Fatal(err)
	}
	if err := regs.Policies.Register(schedPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := regs.Sources.Register(src); err != nil {
		t.Fatal(err)
	}
	return regs
}

func schedConfig() *spec.ProjectConfig {
	return &spec.ProjectConfig{
		Framework: testFramework,
		Vault:     spec.VaultConfig{Backend: "local", Path: "/tmp/x"},
		Sources:   map[string]map[string]any{"aws.iam": {}},
	}
}

// TestRun_ScheduledMode_EvaluatesThenCarriesForward drives the full
// orchestrator pipeline twice against a persistent vault:
//
//	Run 1 (first run): the policy evaluates → passes → state advances.
//	Run 2 (1 minute later): cadence (daily) has not elapsed and the
//	  content hash is unchanged → the policy carries forward; the source
//	  is NOT collected again.
//
// This is the only test that exercises loadPolicyStates →
// decideEvaluation cadence-gate → carry-forward → advancePolicyStates
// through Run() itself.
func TestRun_ScheduledMode_EvaluatesThenCarriesForward(t *testing.T) {
	src := &schedSource{}
	regs := schedRegistries(t, src)
	v := newListVault()

	base := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)

	run := func(now time.Time) Result {
		res, err := Run(context.Background(), &Options{
			Config:        schedConfig(),
			Registries:    regs,
			Vault:         v,
			Mode:          ModeScheduled,
			Stdout:        &bytes.Buffer{},
			Logger:        log.New(&bytes.Buffer{}, false),
			CommitTime:    base,
			Now:           func() time.Time { return now },
			SubmitterOpts: submitter.Options{Disable: true},
			DisableCloud:  true,
		})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}

	// Run 1: first run → evaluate → pass.
	res1 := run(base)
	if res1.Summary.PoliciesPassed != 1 {
		t.Fatalf("run1: PoliciesPassed = %d; want 1", res1.Summary.PoliciesPassed)
	}
	if src.calls != 1 {
		t.Fatalf("run1: source calls = %d; want 1", src.calls)
	}
	// State shard must have been advanced.
	st, err := ReadPolicyState(context.Background(), v, testFramework, "soc2.cc6.1.mfa")
	if err != nil || st == nil {
		t.Fatalf("run1: state not advanced: %v / %+v", err, st)
	}
	if st.LastRunStatus != core.StatusPass {
		t.Errorf("run1: LastRunStatus = %q; want pass", st.LastRunStatus)
	}

	// Run 2: one minute later → cadence not elapsed → carry forward.
	res2 := run(base.Add(time.Minute))
	if res2.Summary.PoliciesCarriedForward != 1 {
		t.Errorf("run2: PoliciesCarriedForward = %d; want 1", res2.Summary.PoliciesCarriedForward)
	}
	if res2.Summary.PoliciesPassed != 0 {
		t.Errorf("run2: PoliciesPassed = %d; want 0 (carried forward)", res2.Summary.PoliciesPassed)
	}
	// The carry-forward must NOT re-collect evidence.
	if src.calls != 1 {
		t.Errorf("run2: source calls = %d; want still 1 (no re-collection on carry-forward)", src.calls)
	}
	// Carry-forward scores as a pass → compliance score 1.0.
	if res2.Summary.ComplianceScore < 0.999 {
		t.Errorf("run2: ComplianceScore = %v; want 1.0", res2.Summary.ComplianceScore)
	}
}

// TestRun_ScheduledMode_DueAfterIntervalReEvaluates confirms that once
// the cadence interval has elapsed the scheduled run re-collects and
// re-evaluates rather than carrying forward.
func TestRun_ScheduledMode_DueAfterIntervalReEvaluates(t *testing.T) {
	src := &schedSource{}
	regs := schedRegistries(t, src)
	v := newListVault()
	base := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)

	run := func(now time.Time) Result {
		res, err := Run(context.Background(), &Options{
			Config:        schedConfig(),
			Registries:    regs,
			Vault:         v,
			Mode:          ModeScheduled,
			Stdout:        &bytes.Buffer{},
			Logger:        log.New(&bytes.Buffer{}, false),
			CommitTime:    base,
			Now:           func() time.Time { return now },
			SubmitterOpts: submitter.Options{Disable: true},
			DisableCloud:  true,
		})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}

	run(base) // first run
	// 25h later: daily interval (23h with slack) elapsed → re-evaluate.
	res := run(base.Add(25 * time.Hour))
	if res.Summary.PoliciesPassed != 1 {
		t.Errorf("PoliciesPassed = %d; want 1 (cadence elapsed → re-evaluate)", res.Summary.PoliciesPassed)
	}
	if src.calls != 2 {
		t.Errorf("source calls = %d; want 2 (re-collected after interval)", src.calls)
	}
}
