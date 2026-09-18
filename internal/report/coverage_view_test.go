package report_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/report"
)

func coverageSnapshot() *report.Snapshot {
	return &report.Snapshot{
		View: report.ViewCoverage, Framework: "soc2", PeriodID: "2026-Q2",
		Coverage: &report.CoverageView{
			Controls: 3, Automated: 1, Manual: 2,
			Evaluated: 1, NotEvaluated: 2,
			ManualOnFile: 0, ManualMissing: 2,
			Rows: []report.CoverageRow{
				{ControlID: "CC1.1", Assurance: "manual", ManualPolicies: 2, Policies: 2,
					Status: "not evaluated", Note: "no policy ran in this period (cadence: annual)"},
				{ControlID: "CC3.1", Assurance: "manual", ManualPolicies: 1, Policies: 1,
					Status: "not evaluated", Note: "no policy ran in this period (cadence: annual)"},
				{ControlID: "CC6.1", Assurance: "automated", AutomatedPolicies: 4, ManualPolicies: 1,
					Evaluated: 4, Policies: 5, Status: "pass"},
			},
		},
	}
}

// The headline is the whole point of the view: a framework can read
// "fully covered" while most of that coverage is documents nobody read.
func TestFormatTextCoverage_HeadlineSeparatesInspectionFromPaperwork(t *testing.T) {
	var buf bytes.Buffer
	if err := report.FormatText(&buf, coverageSnapshot()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"3 of 3 controls have a check",
		"1 automated",
		"verified by inspecting your infrastructure",
		"2 manual",
		"contents are not inspected",
		"1 evaluated, 2 not evaluated",
		"0 manual control(s) with evidence on file, 2 without",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// A cadence longer than the audit period legitimately produces no result
// for most of the year. The view must say so, or every Q1-Q3 report
// reads like an outage.
func TestFormatTextCoverage_ExplainsSupraPeriodCadence(t *testing.T) {
	var buf bytes.Buffer
	if err := report.FormatText(&buf, coverageSnapshot()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "cadence: annual") {
		t.Errorf("a not-evaluated row must name its cadence:\n%s", out)
	}
	if !strings.Contains(out, "longer than this period") {
		t.Errorf("the view must explain why a supra-period cadence shows as not evaluated:\n%s", out)
	}
}

func TestFormatTextCoverage_MarksOverriddenControls(t *testing.T) {
	snap := coverageSnapshot()
	snap.Coverage.Rows[2].Overridden = true
	snap.Coverage.Overridden = 1
	var buf bytes.Buffer
	if err := report.FormatText(&buf, snap); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "(overridden)") {
		t.Errorf("an overridden control must be marked in its row:\n%s", out)
	}
	if !strings.Contains(out, "1 control(s) running in a mode the project overrode") {
		t.Errorf("overridden controls must appear in the headline:\n%s", out)
	}
}

func TestFormatCSVCoverage_RowsAndHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := report.FormatCSV(&buf, coverageSnapshot()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "control_id,assurance,automated_policies,manual_policies") {
		t.Errorf("unexpected CSV header:\n%s", out)
	}
	if !strings.Contains(out, "CC6.1,automated,4,1,4,5,pass,false,") {
		t.Errorf("CC6.1 row missing or malformed:\n%s", out)
	}
}

func TestFormatCSV_NilCoverageViewEmitsHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := report.FormatCSV(&buf, &report.Snapshot{View: report.ViewCoverage}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(strings.TrimSpace(buf.String()), "\n"); got != 0 {
		t.Errorf("nil view should emit a header and nothing else; got %d extra lines:\n%s", got, buf.String())
	}
}

func TestFormatTextCoverage_NilViewDoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	if err := report.FormatText(&buf, &report.Snapshot{View: report.ViewCoverage}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no runs in this period") {
		t.Errorf("unexpected empty-state output: %q", buf.String())
	}
}

func TestFormatTextCoverage_Deterministic(t *testing.T) {
	snap := coverageSnapshot()
	var first string
	for i := 0; i < 10; i++ {
		var buf bytes.Buffer
		if err := report.FormatText(&buf, snap); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = buf.String()
			continue
		}
		if buf.String() != first {
			t.Fatalf("output is not byte-identical across invocations (run %d)", i)
		}
	}
}

// TestBuildCoverage_NamesControlsThatNeverRan is the regression for the
// blind spot that motivated the view.
//
// Cadence is independent of the audit period. A framework whose manual
// policies are annual produces no result at all for those controls in
// three quarters out of four — not a failure, not a skip, simply absent
// from the period folder. A view built only from what the vault contains
// would show a clean bill of health over the controls that happened to
// run, which is the deception in miniature.
func TestBuildCoverage_NamesControlsThatNeverRan(t *testing.T) {
	v, _ := makeVault(t, []runSeed{{
		framework: "soc2", periodID: "2026-Q2", runID: "run-aaaa",
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: "soc2.cc6.1.mfa", Status: core.StatusPass, EvidenceMode: core.EvidenceModeAutomated},
		},
	}})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: "soc2", PeriodID: "2026-Q2", View: report.ViewCoverage,
		Controls: []core.Control{{ID: "CC1.1"}, {ID: "CC6.1"}},
		Policies: []core.Policy{
			{ID: "soc2.cc6.1.mfa", EvidenceMode: core.EvidenceModeAutomated, Cadence: "daily",
				Controls: []core.ControlRef{{ControlID: "CC6.1"}}},
			{ID: "soc2.cc1.1.training", EvidenceMode: core.EvidenceModeManual, Cadence: "annual",
				Controls: []core.ControlRef{{ControlID: "CC1.1"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cov := snap.Coverage
	if cov.Controls != 2 || cov.Automated != 1 || cov.Manual != 1 {
		t.Errorf("totals = %+v; want 2 controls, 1 automated, 1 manual", cov)
	}
	if cov.Evaluated != 1 || cov.NotEvaluated != 1 {
		t.Errorf("Evaluated/NotEvaluated = %d/%d; want 1/1", cov.Evaluated, cov.NotEvaluated)
	}
	if cov.ManualMissing != 1 {
		t.Errorf("ManualMissing = %d; want 1 — the annual control has no document this period", cov.ManualMissing)
	}
	if len(cov.Rows) != 2 || cov.Rows[0].ControlID != "CC1.1" {
		t.Fatalf("rows = %+v; want one per control, sorted by control ID", cov.Rows)
	}
	if cov.Rows[0].Status != "not evaluated" {
		t.Errorf("CC1.1 status = %q; want %q", cov.Rows[0].Status, "not evaluated")
	}
	if !strings.Contains(cov.Rows[0].Note, "annual") {
		t.Errorf("CC1.1 note = %q; want it to name the cadence so a reader can tell expected from broken", cov.Rows[0].Note)
	}
}

// A project can reconfigure a policy away from the framework's declared
// evidence mode. The run's own account of itself wins — describing the
// control from the catalog alone would describe something that did not
// happen.
func TestBuildCoverage_RunRecordOutranksTheCatalog(t *testing.T) {
	v, _ := makeVault(t, []runSeed{{
		framework: "soc2", periodID: "2026-Q2", runID: "run-aaaa",
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{{
			PolicyID: "soc2.cc6.1.mfa", Status: core.StatusPass,
			EvidenceMode: core.EvidenceModeManual, EvidenceModeOverridden: true,
		}},
	}})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: "soc2", PeriodID: "2026-Q2", View: report.ViewCoverage,
		Controls: []core.Control{{ID: "CC6.1"}},
		// The catalog says this control is automated.
		Policies: []core.Policy{{ID: "soc2.cc6.1.mfa", EvidenceMode: core.EvidenceModeAutomated,
			Controls: []core.ControlRef{{ControlID: "CC6.1"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.Coverage.Rows[0].Assurance; got != "manual" {
		t.Errorf("assurance = %q; want manual — the run downgraded this check to a document", got)
	}
	if !snap.Coverage.Rows[0].Overridden || snap.Coverage.Overridden != 1 {
		t.Error("the override must be visible; a control degraded with no trail is the failure this records")
	}
	if snap.Coverage.Automated != 0 || snap.Coverage.Manual != 1 {
		t.Errorf("totals = %+v; want the override reflected in the headline", snap.Coverage)
	}
}
