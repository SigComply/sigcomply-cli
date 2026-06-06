package orchestrator

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
)

// minimalConfig returns the smallest ProjectConfig that lets Run reach
// the planner; the framework registration is handled in each test.
func minimalConfig() *spec.ProjectConfig {
	return &spec.ProjectConfig{
		Framework: "soc2",
		Vault:     spec.VaultConfig{Backend: "local", Config: map[string]any{"path": "/tmp/x"}},
	}
}

func TestRun_RejectsNilConfig(t *testing.T) {
	_, err := Run(context.Background(), &Options{Registries: registry.NewSet(), Vault: newInMem()})
	if err == nil {
		t.Fatalf("want error")
	}
}

func TestRun_RejectsNilRegistries(t *testing.T) {
	_, err := Run(context.Background(), &Options{Config: minimalConfig(), Vault: newInMem()})
	if err == nil {
		t.Fatalf("want error")
	}
}

func TestRun_RejectsNilVault(t *testing.T) {
	_, err := Run(context.Background(), &Options{Config: minimalConfig(), Registries: registry.NewSet()})
	if err == nil {
		t.Fatalf("want error")
	}
}

func TestRun_PlanErrorIsExitConfig(t *testing.T) {
	// No framework registered → planner fails.
	res, err := Run(context.Background(), &Options{
		Config:     minimalConfig(),
		Registries: registry.NewSet(),
		Vault:      newInMem(),
		Logger:     log.New(&bytes.Buffer{}, false),
		Stdout:     &bytes.Buffer{},
		Now:        func() time.Time { return time.Now().UTC() },
	})
	if err == nil {
		t.Fatalf("expected planner error")
	}
	if res.ExitCode != ExitConfig {
		t.Errorf("ExitCode = %d; want %d", res.ExitCode, ExitConfig)
	}
}

// runRenderAndExitCode is the function under test. The orchestrator
// instantiates and calls it inline; we cover the branches directly.
func TestRenderAndExitCode_PassExitOK(t *testing.T) {
	var buf bytes.Buffer
	plan := &planner.RunPlan{Framework: "soc2", Period: planner.Period{ID: "2026-Q1"}}
	results := []core.PolicyResult{
		{PolicyID: "p1", Status: core.StatusPass},
		{PolicyID: "p2", Status: core.StatusNA},
	}
	code := renderAndExitCode(&buf, plan, results, spec.CIConfig{})
	if code != ExitOK {
		t.Errorf("code = %d; want %d", code, ExitOK)
	}
	if !strings.Contains(buf.String(), "soc2/2026-Q1") {
		t.Errorf("output missing header: %q", buf.String())
	}
}

func TestRenderAndExitCode_FailWithDefaultsIsViolation(t *testing.T) {
	plan := &planner.RunPlan{Framework: "soc2"}
	results := []core.PolicyResult{{PolicyID: "p1", Status: core.StatusFail}}
	code := renderAndExitCode(&bytes.Buffer{}, plan, results, spec.CIConfig{})
	if code != ExitViolation {
		t.Errorf("code = %d; want %d", code, ExitViolation)
	}
}

func TestRenderAndExitCode_FailWithFailOnViolationDisabled(t *testing.T) {
	plan := &planner.RunPlan{Framework: "soc2"}
	results := []core.PolicyResult{{PolicyID: "p1", Status: core.StatusFail}}
	disabled := false
	code := renderAndExitCode(&bytes.Buffer{}, plan, results, spec.CIConfig{FailOnViolation: &disabled})
	if code != ExitOK {
		t.Errorf("code = %d; want %d (fail_on_violation disabled)", code, ExitOK)
	}
}

func TestRenderAndExitCode_ErrorWinsOverFail(t *testing.T) {
	plan := &planner.RunPlan{Framework: "soc2"}
	results := []core.PolicyResult{
		{PolicyID: "p1", Status: core.StatusError},
		{PolicyID: "p2", Status: core.StatusFail},
	}
	code := renderAndExitCode(&bytes.Buffer{}, plan, results, spec.CIConfig{})
	if code != ExitExecution {
		t.Errorf("code = %d; want %d", code, ExitExecution)
	}
}

// TestRenderAndExitCode_SkipExplanationsAreLoud verifies that skipped
// controls are surfaced with the concrete reason — an unbound required
// slot names the evidence types no source provided, and the operator is
// warned a green-but-skipping run is not a passing audit.
func TestRenderAndExitCode_SkipExplanationsAreLoud(t *testing.T) {
	unboundSlot := core.Policy{
		ID: "soc2.cc6.1.unbound",
		Slots: map[string]core.Slot{
			"evidence": {Accepts: []string{"directory_user"}, Required: true, Cardinality: core.SlotOneOrMore},
		},
	}
	boundSlot := core.Policy{
		ID: "soc2.cc7.2.empty",
		Slots: map[string]core.Slot{
			"evidence": {Accepts: []string{"audit_log_trail"}, Required: true, Cardinality: core.SlotOneOrMore},
		},
	}
	plan := &planner.RunPlan{
		Framework: "soc2",
		Period:    planner.Period{ID: "2026-Q1"},
		Policies: []planner.PlannedPolicy{
			{Spec: unboundSlot, Bindings: map[string][]planner.Binding{}},
			{Spec: boundSlot, Bindings: map[string][]planner.Binding{
				"evidence": {{SourceID: "aws.cloudtrail", AcceptedTypes: []string{"audit_log_trail"}}},
			}},
		},
	}
	results := []core.PolicyResult{
		{PolicyID: "soc2.cc6.1.unbound", Status: core.StatusSkip},
		{PolicyID: "soc2.cc7.2.empty", Status: core.StatusSkip},
	}
	var buf bytes.Buffer
	code := renderAndExitCode(&buf, plan, results, spec.CIConfig{})
	if code != ExitOK {
		t.Errorf("code = %d; want %d (skips alone are not a violation)", code, ExitOK)
	}
	out := buf.String()
	for _, want := range []string{
		"2 control(s) were SKIPPED",
		"no configured source emits [directory_user]",
		"bound source(s) returned no evidence records",
		"NOT a passing audit",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("skip output missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// To exercise Run()'s "no-cloud" path and the "force-cloud / no token"
// path, we register SOC 2 with an empty framework so the run produces
// zero policies. That keeps the test under 1 ms while still covering
// the cloud-decision switch.
type emptyFramework struct{}

func (*emptyFramework) ID() string                 { return "soc2" }
func (*emptyFramework) Version() string            { return "v0" }
func (*emptyFramework) Controls() []core.Control   { return nil }
func (*emptyFramework) Policies() []core.PolicyRef { return nil }

func TestRun_NoCloudPath(t *testing.T) {
	regs := registry.NewSet()
	if err := regs.Frameworks.Register(&emptyFramework{}); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), &Options{
		Config:       minimalConfig(),
		Registries:   regs,
		Vault:        newInMem(),
		Stdout:       &bytes.Buffer{},
		Logger:       log.New(&bytes.Buffer{}, false),
		Now:          func() time.Time { return time.Now().UTC() },
		DisableCloud: true,
		SubmitterOpts: submitter.Options{
			Disable: true,
			BaseURL: "https://example.com",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Submitted {
		t.Errorf("Submitted = true; want false (--no-cloud)")
	}
}

func TestRun_ForceCloud_NoTokenIsHandled(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SIGCOMPLY_ID_TOKEN", "")
	t.Setenv("ID_TOKEN", "")
	regs := registry.NewSet()
	if err := regs.Frameworks.Register(&emptyFramework{}); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), &Options{
		Config:     minimalConfig(),
		Registries: regs,
		Vault:      newInMem(),
		Stdout:     &bytes.Buffer{},
		Logger:     log.New(&bytes.Buffer{}, false),
		Now:        func() time.Time { return time.Now().UTC() },
		ForceCloud: true,
		SubmitterOpts: submitter.Options{
			Force:   true,
			BaseURL: "https://example.com",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Force-cloud without an OIDC token logs a warning and proceeds; the
	// run itself does not fail.
	if res.Submitted {
		t.Errorf("Submitted = true; want false (no token)")
	}
}

func TestRun_CapturePayloadPathTakesPrecedence(t *testing.T) {
	tmp := t.TempDir()
	regs := registry.NewSet()
	if err := regs.Frameworks.Register(&emptyFramework{}); err != nil {
		t.Fatal(err)
	}
	out := tmp + "/captured.json"
	res, err := Run(context.Background(), &Options{
		Config:             minimalConfig(),
		Registries:         regs,
		Vault:              newInMem(),
		Stdout:             &bytes.Buffer{},
		Logger:             log.New(&bytes.Buffer{}, false),
		Now:                func() time.Time { return time.Now().UTC() },
		CapturePayloadPath: out,
		SubmitterOpts:      submitter.Options{BaseURL: "https://x"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Submitted {
		t.Errorf("Submitted should be false when --capture-cloud-payload is set")
	}
}

func TestEmitPlanWarnings_CoverageSkew(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, true) // verbose: include Debugf detail lines
	plan := &planner.RunPlan{
		Policies: []planner.PlannedPolicy{
			{
				Spec: core.Policy{ID: "soc2.cc6.1.mfa_enforced_admins"},
				CoverageGaps: []planner.CoverageGap{
					{
						Slot:        "user_directory",
						Accepts:     []string{"directory_user.v2"},
						Source:      "okta",
						SourceEmits: []string{"directory_user"},
					},
				},
			},
		},
	}
	emitPlanWarnings(logger, plan, time.Now().UTC())
	out := buf.String()
	if !strings.Contains(out, "coverage-skew") {
		t.Fatalf("expected coverage-skew warning; got:\n%s", out)
	}
	if !strings.Contains(out, "okta") || !strings.Contains(out, "soc2.cc6.1.mfa_enforced_admins") {
		t.Errorf("warning should name the source and policy; got:\n%s", out)
	}
}
