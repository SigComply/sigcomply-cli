package planner

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// stubFramework is the smallest thing validateApplicability reads: an
// ID and a control catalog.
type stubFramework struct {
	controls []core.Control
}

func (s stubFramework) ID() string                 { return "iso27001" }
func (s stubFramework) Version() string            { return "2022" }
func (s stubFramework) Controls() []core.Control   { return s.controls }
func (s stubFramework) Policies() []core.PolicyRef { return nil }

func testFramework() stubFramework {
	return stubFramework{controls: []core.Control{
		{ID: "A.5.1", Name: "Policies for information security"},
		{ID: "C.9.2", Name: "Internal audit", Kind: core.ControlKindManagementSystem},
	}}
}

// TestValidateApplicability_RejectsExcludedManagementSystemControl is
// the load-bearing case: without it the control cascade would honor
// the exclusion, mark every policy under the clause N/A, and *raise*
// the compliance score for declining to have an ISMS.
func TestValidateApplicability_RejectsExcludedManagementSystemControl(t *testing.T) {
	cfg := &spec.ProjectConfig{Controls: map[string]spec.ControlConfig{
		"C.9.2": {Applicability: "not_applicable", Reason: "we are small"},
	}}
	err := validateApplicability(cfg, testFramework())
	if err == nil {
		t.Fatal("excluding a management-system requirement must be a config error")
	}
	for _, want := range []string{"C.9.2", "management-system requirement", "not_applicable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestValidateApplicability_AllowsEverythingElse: excluding an Annex A
// control is the whole point of a Statement of Applicability, and
// marking a clause explicitly applicable is a no-op, not an error.
func TestValidateApplicability_AllowsEverythingElse(t *testing.T) {
	for name, controls := range map[string]map[string]spec.ControlConfig{
		"annex A exclusion":        {"A.5.1": {Applicability: "not_applicable", Reason: "no in-house policy suite"}},
		"clause marked applicable": {"C.9.2": {Applicability: "applicable"}},
		"clause left default":      {"C.9.2": {ApprovedBy: "ciso@example.com"}},
		"no control config":        nil,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateApplicability(&spec.ProjectConfig{Controls: controls}, testFramework()); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
