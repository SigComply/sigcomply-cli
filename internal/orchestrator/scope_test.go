package orchestrator

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/scope"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

func incompleteReport() *scope.Report {
	return &scope.Report{
		Status:  scope.StatusIncomplete,
		Sources: []scope.SourceReport{{SourceID: sourceOkta, State: scope.SourceNotConfigured}, {SourceID: sourceGitHub, State: scope.SourceOK}},
		Missing: []string{sourceOkta},
	}
}

func passingResults() []core.PolicyResult {
	return []core.PolicyResult{{PolicyID: "p1", Status: core.StatusPass}}
}

// The whole point: every policy passes, yet the run must go red because
// it never looked at an estate the operator declared.
func TestRenderAndExitCode_IncompleteScopeFailsAnAllPassingRun(t *testing.T) {
	var buf bytes.Buffer
	plan := &planner.RunPlan{Framework: testFramework}
	code := renderAndExitCode(&buf, plan, passingResults(), spec.CIConfig{}, incompleteReport())
	if code != ExitViolation {
		t.Fatalf("exit = %d; want %d (ExitViolation)", code, ExitViolation)
	}
	out := buf.String()
	if !strings.Contains(out, "SCOPE INCOMPLETE") {
		t.Errorf("stdout missing the scope banner:\n%s", out)
	}
	if !strings.Contains(out, sourceOkta) {
		t.Errorf("stdout does not name the uncovered source:\n%s", out)
	}
	// The covered source must not be listed as a problem.
	if strings.Contains(out, "github —") {
		t.Errorf("stdout lists a covered source as missing:\n%s", out)
	}
}

// Consistency with every other failure: an operator who has opted out of
// failing builds gets the warning, not a red build.
func TestRenderAndExitCode_ScopeRespectsFailOnViolation(t *testing.T) {
	var buf bytes.Buffer
	off := false
	code := renderAndExitCode(&buf, &planner.RunPlan{}, passingResults(), spec.CIConfig{FailOnViolation: &off}, incompleteReport())
	if code != ExitOK {
		t.Fatalf("exit = %d; want %d with fail_on_violation:false", code, ExitOK)
	}
	if !strings.Contains(buf.String(), "SCOPE INCOMPLETE") {
		t.Error("the banner must still print even when the build is not failed")
	}
}

func TestRenderAndExitCode_CompleteAndUndeclaredAreSilent(t *testing.T) {
	for _, rep := range []*scope.Report{
		nil,
		{Status: scope.StatusUndeclared},
		{Status: scope.StatusComplete, Sources: []scope.SourceReport{{SourceID: sourceGitHub, State: scope.SourceOK}}},
	} {
		var buf bytes.Buffer
		code := renderAndExitCode(&buf, &planner.RunPlan{}, passingResults(), spec.CIConfig{}, rep)
		if code != ExitOK {
			t.Errorf("exit = %d; want ExitOK for %+v", code, rep)
		}
		if strings.Contains(buf.String(), "SCOPE") {
			t.Errorf("unexpected scope output for %+v:\n%s", rep, buf.String())
		}
	}
}

// An execution error still outranks a scope failure.
func TestRenderAndExitCode_ErrorOutranksScope(t *testing.T) {
	var buf bytes.Buffer
	results := []core.PolicyResult{{PolicyID: "p1", Status: core.StatusError}}
	if code := renderAndExitCode(&buf, &planner.RunPlan{}, results, spec.CIConfig{}, incompleteReport()); code != ExitExecution {
		t.Fatalf("exit = %d; want %d (ExitExecution)", code, ExitExecution)
	}
}

// Opting in is what adds the block. A project that declares nothing must
// keep a byte-identical summary.json shape across the upgrade.
//
// Both inputs matter: nil is the trivial case, but evaluateScope actually
// returns a non-nil "undeclared" report, and assigning that into the
// `any` field defeats omitempty — which is exactly the bug this covers.
func TestSummaryFromResults_ScopeOmittedWhenUndeclared(t *testing.T) {
	plan := &planner.RunPlan{Framework: testFramework, Period: planner.Period{ID: testPeriodID}}
	for _, rep := range []*scope.Report{
		nil,
		{Status: scope.StatusUndeclared, PoliciesUnbound: 82},
	} {
		s := summaryFromResults(passingResults(), "run1", plan, time.Now(), rep)
		body, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "\"scope\"") {
			t.Errorf("summary.json carries a scope key for %+v:\n%s", rep, body)
		}
	}
}

func TestSummaryFromResults_ScopePersisted(t *testing.T) {
	plan := &planner.RunPlan{Framework: testFramework, Period: planner.Period{ID: testPeriodID}}
	s := summaryFromResults(passingResults(), "run1", plan, time.Now(), incompleteReport())
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Scope scope.Report `json:"scope"`
	}
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatal(err)
	}
	if back.Scope.Status != scope.StatusIncomplete {
		t.Errorf("persisted status = %q; want incomplete", back.Scope.Status)
	}
	if len(back.Scope.Missing) != 1 || back.Scope.Missing[0] != sourceOkta {
		t.Errorf("persisted Missing = %v", back.Scope.Missing)
	}
}

func TestScopeStateExplanation_CoversEveryState(t *testing.T) {
	for _, s := range []scope.SourceState{scope.SourceNotConfigured, scope.SourceNotBound, scope.SourceNoRecords} {
		if got := scopeStateExplanation(s); got == "" || got == "covered" {
			t.Errorf("state %q has no actionable explanation (got %q)", s, got)
		}
	}
}
