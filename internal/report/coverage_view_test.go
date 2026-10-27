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
		View: report.ViewCoverage, Framework: frameworkSOC2, PeriodID: testPeriodQ2,
		Coverage: &report.CoverageView{
			Controls: 3, Automated: 1, Manual: 2,
			Evaluated: 1, NotEvaluated: 2, AutomatedInspected: 1,
			ManualOnFile: 0, ManualMissing: 2,
			Rows: []report.CoverageRow{
				{ControlID: ctrlCC11, Assurance: assuranceManual, ManualPolicies: 2, Policies: 2,
					Status: statusNotEvaluated, Note: "no policy ran in this period (cadence: annual)"},
				{ControlID: "CC3.1", Assurance: assuranceManual, ManualPolicies: 1, Policies: 1,
					Status: statusNotEvaluated, Note: "no policy ran in this period (cadence: annual)"},
				{ControlID: ctrlCC61, Assurance: "automated", AutomatedPolicies: 4, ManualPolicies: 1,
					Evaluated: 4, Policies: 5, Status: statusPass},
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
		"3 of 3 catalog controls have a check",
		"1 automated",
		"an automated check is mapped",
		"2 manual",
		"contents are not inspected",
		"1 evaluated, 2 not evaluated",
		"1 automated control(s): 1 inspected, 0 skipped, 0 waived or not applicable, 0 not evaluated or errored",
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
	if !strings.HasPrefix(out, "control_id,kind,assurance,automated_policies,manual_policies") {
		t.Errorf("unexpected CSV header:\n%s", out)
	}
	if !strings.Contains(out, "CC6.1,catalog,automated,4,1,4,5,pass,false,") {
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
		framework: frameworkSOC2, periodID: testPeriodQ2, runID: testRunID,
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: testPolicyMFA, Status: core.StatusPass, EvidenceMode: core.EvidenceModeAutomated},
		},
	}})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ2, View: report.ViewCoverage,
		Controls: []core.Control{{ID: ctrlCC11}, {ID: ctrlCC61}},
		Policies: []core.Policy{
			{ID: testPolicyMFA, EvidenceMode: core.EvidenceModeAutomated, Cadence: cadenceDaily,
				Controls: []core.ControlRef{{ControlID: ctrlCC61}}},
			{ID: "soc2.cc1.1.training", EvidenceMode: core.EvidenceModeManual, Cadence: cadenceAnnual,
				Controls: []core.ControlRef{{ControlID: ctrlCC11}}},
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
	if len(cov.Rows) != 2 || cov.Rows[0].ControlID != ctrlCC11 {
		t.Fatalf("rows = %+v; want one per control, sorted by control ID", cov.Rows)
	}
	if cov.Rows[0].Status != statusNotEvaluated {
		t.Errorf("CC1.1 status = %q; want %q", cov.Rows[0].Status, statusNotEvaluated)
	}
	if !strings.Contains(cov.Rows[0].Note, cadenceAnnual) {
		t.Errorf("CC1.1 note = %q; want it to name the cadence so a reader can tell expected from broken", cov.Rows[0].Note)
	}
}

// A project can reconfigure a policy away from the framework's declared
// evidence mode. The run's own account of itself wins — describing the
// control from the catalog alone would describe something that did not
// happen.
func TestBuildCoverage_RunRecordOutranksTheCatalog(t *testing.T) {
	v, _ := makeVault(t, []runSeed{{
		framework: frameworkSOC2, periodID: testPeriodQ2, runID: testRunID,
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{{
			PolicyID: testPolicyMFA, Status: core.StatusPass,
			EvidenceMode: core.EvidenceModeManual, EvidenceModeOverridden: true,
		}},
	}})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ2, View: report.ViewCoverage,
		Controls: []core.Control{{ID: ctrlCC61}},
		// The catalog says this control is automated.
		Policies: []core.Policy{{ID: testPolicyMFA, EvidenceMode: core.EvidenceModeAutomated,
			Controls: []core.ControlRef{{ControlID: ctrlCC61}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.Coverage.Rows[0].Assurance; got != assuranceManual {
		t.Errorf("assurance = %q; want manual — the run downgraded this check to a document", got)
	}
	if !snap.Coverage.Rows[0].Overridden || snap.Coverage.Overridden != 1 {
		t.Error("the override must be visible; a control degraded with no trail is the failure this records")
	}
	if snap.Coverage.Automated != 0 || snap.Coverage.Manual != 1 {
		t.Errorf("totals = %+v; want the override reflected in the headline", snap.Coverage)
	}
}

// ctrlCC66 is the control whose automated check skips beside a passing
// document.
const ctrlCC66 = "CC6.6"

// TestBuildCoverage_AutomatedControlWhoseChecksSkipped is the regression
// for the headline that called every automated control "verified by
// inspecting your infrastructure". A control is automated because an
// automated check is mapped to it; whether that check inspected
// anything this period is a separate fact. A run with no credentials
// for a source skips every policy that reads it, and the control must
// be counted as skipped, not inspected.
func TestBuildCoverage_AutomatedControlWhoseChecksSkipped(t *testing.T) {
	v, _ := makeVault(t, []runSeed{{
		framework: frameworkSOC2, periodID: testPeriodQ2, runID: testRunID,
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: testPolicyMFA, Status: core.StatusPass, EvidenceMode: core.EvidenceModeAutomated},
			{PolicyID: "soc2.cc6.6.fw", Status: core.StatusSkip, EvidenceMode: core.EvidenceModeAutomated},
			{PolicyID: "soc2.cc6.6.doc", Status: core.StatusPass, EvidenceMode: core.EvidenceModeManual},
			{PolicyID: "soc2.cc7.1.err", Status: core.StatusError, EvidenceMode: core.EvidenceModeAutomated},
		},
	}})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ2, View: report.ViewCoverage,
		Controls: []core.Control{{ID: ctrlCC61}, {ID: ctrlCC66}, {ID: "CC7.1"}, {ID: "CC7.2"}},
		Policies: []core.Policy{
			{ID: testPolicyMFA, EvidenceMode: core.EvidenceModeAutomated, Controls: []core.ControlRef{{ControlID: ctrlCC61}}},
			// CC6.6: the automated check skipped; a passing document
			// beside it must not make the control count as inspected.
			{ID: "soc2.cc6.6.fw", EvidenceMode: core.EvidenceModeAutomated, Controls: []core.ControlRef{{ControlID: ctrlCC66}}},
			{ID: "soc2.cc6.6.doc", EvidenceMode: core.EvidenceModeManual, Controls: []core.ControlRef{{ControlID: ctrlCC66}}},
			{ID: "soc2.cc7.1.err", EvidenceMode: core.EvidenceModeAutomated, Controls: []core.ControlRef{{ControlID: "CC7.1"}}},
			{ID: "soc2.cc7.2.none", EvidenceMode: core.EvidenceModeAutomated, Controls: []core.ControlRef{{ControlID: "CC7.2"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cov := snap.Coverage
	if cov.Automated != 4 {
		t.Fatalf("Automated = %d; want 4", cov.Automated)
	}
	if cov.AutomatedInspected != 1 || cov.AutomatedSkipped != 1 {
		t.Errorf("AutomatedInspected/AutomatedSkipped = %d/%d; want 1/1 (CC6.1 inspected, CC6.6 skipped; CC7.1 errored, CC7.2 never ran)",
			cov.AutomatedInspected, cov.AutomatedSkipped)
	}

	var buf bytes.Buffer
	if err := report.FormatText(&buf, snap); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "verified by inspecting") {
		t.Errorf("headline still claims every automated control was inspected:\n%s", out)
	}
	if !strings.Contains(out, "4 automated control(s): 1 inspected, 1 skipped, 0 waived or not applicable, 2 not evaluated or errored") {
		t.Errorf("headline must split automated controls by what this period's runs did:\n%s", out)
	}
}

// TestBuildCoverage_ExceptedControlsAreNotInspected is the regression
// for a whole-policy waiver and a not-applicable declaration being
// reported as an inspection and a skip. A whole-policy exception stops
// collection and evaluation before either starts, so its waived result
// stands for nothing examined; only a resource-scoped waiver, which is
// applied to a real evaluation's violations, is an inspection. And na
// is a deliberate decision, not a source that was never configured.
func TestBuildCoverage_ExceptedControlsAreNotInspected(t *testing.T) {
	const (
		ctrlWholeWaiver = "CC8.1"
		ctrlScopedWaive = "CC6.2"
		ctrlNA          = "CC6.3"
		ctrlCarried     = "CC6.4"
	)
	v, _ := makeVault(t, []runSeed{{
		framework: frameworkSOC2, periodID: testPeriodQ2, runID: testRunID,
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: "p.whole", Status: core.StatusWaived, EvidenceMode: core.EvidenceModeAutomated},
			{PolicyID: "p.scoped", Status: core.StatusWaived, ResourcesEvaluated: 3, EvidenceMode: core.EvidenceModeAutomated},
			{PolicyID: "p.na", Status: core.StatusNA, EvidenceMode: core.EvidenceModeAutomated},
			// Carried forward only ever follows a pass, so it points at
			// a prior signed inspection.
			{PolicyID: "p.carried", Status: core.StatusCarriedForward, EvidenceMode: core.EvidenceModeAutomated},
		},
	}})

	auto := func(id, ctrl string) core.Policy {
		return core.Policy{ID: id, EvidenceMode: core.EvidenceModeAutomated, Controls: []core.ControlRef{{ControlID: ctrl}}}
	}
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ2, View: report.ViewCoverage,
		Controls: []core.Control{{ID: ctrlWholeWaiver}, {ID: ctrlScopedWaive}, {ID: ctrlNA}, {ID: ctrlCarried}},
		Policies: []core.Policy{
			auto("p.whole", ctrlWholeWaiver), auto("p.scoped", ctrlScopedWaive),
			auto("p.na", ctrlNA), auto("p.carried", ctrlCarried),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cov := snap.Coverage
	if cov.AutomatedInspected != 2 || cov.AutomatedSkipped != 0 || cov.AutomatedExcepted != 2 {
		t.Errorf("inspected/skipped/excepted = %d/%d/%d; want 2/0/2 (scoped waiver and carry-forward inspected; whole-policy waiver and na excepted)",
			cov.AutomatedInspected, cov.AutomatedSkipped, cov.AutomatedExcepted)
	}

	var buf bytes.Buffer
	if err := report.FormatText(&buf, snap); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "4 automated control(s): 2 inspected, 0 skipped, 2 waived or not applicable, 0 not evaluated or errored") {
		t.Errorf("headline must count excepted controls apart from inspected and skipped ones:\n%s", out)
	}
	if !strings.Contains(out, "waived as a whole or marked not applicable in the project's exceptions") {
		t.Errorf("footer must explain the waived-or-not-applicable count:\n%s", out)
	}
}

// TestBuildScope_ShowsErroredPolicies is the regression for a gap in the
// scope view: it listed only skipped controls, so an errored policy —
// semantically an unevaluated control, and one that stays in the
// compliance-score denominator counting against it — was invisible
// exactly where a reader goes to find unevaluated controls.
func TestBuildScope_ShowsErroredPolicies(t *testing.T) {
	v, _ := makeVault(t, []runSeed{{
		framework: frameworkSOC2, periodID: testPeriodQ2, runID: testRunID,
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: "p.skipped", Status: core.StatusSkip, Diag: map[string]any{"reason": reasonNoRecords}},
			{PolicyID: "p.errored", Status: core.StatusError, Diag: map[string]any{"collect_error": reasonAccessDenied}},
			{PolicyID: "p.passed", Status: core.StatusPass},
		},
	}})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ2, View: report.ViewScope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Scope.Skipped) != 2 {
		t.Fatalf("got %d unevaluated rows; want 2 (the skip and the error)", len(snap.Scope.Skipped))
	}

	byID := map[string]report.SkippedPolicy{}
	for _, s := range snap.Scope.Skipped {
		byID[s.PolicyID] = s
	}
	e, ok := byID["p.errored"]
	if !ok {
		t.Fatal("the errored policy is missing from the scope view")
	}
	if e.Status != "error" {
		t.Errorf("status = %q; want error — a skip and an error must be distinguishable", e.Status)
	}
	if e.Reason != reasonAccessDenied {
		t.Errorf("reason = %q; want the collector's diagnostic, not a generic placeholder", e.Reason)
	}
}

// TestBuildLatest_CarriesTheReason closes the other half: `--view latest`
// printed a bare "error" while the explanation sat unread in the vault.
func TestBuildLatest_CarriesTheReason(t *testing.T) {
	v, _ := makeVault(t, []runSeed{{
		framework: frameworkSOC2, periodID: testPeriodQ2, runID: testRunID,
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: "p.errored", Status: core.StatusError, Diag: map[string]any{"collect_error": reasonAccessDenied}},
		},
	}})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ2, View: report.ViewLatest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.Latest.Policies[0].Reason; got != reasonAccessDenied {
		t.Errorf("Reason = %q; want the collector's diagnostic", got)
	}

	var buf bytes.Buffer
	if err := report.FormatText(&buf, snap); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "access denied") {
		t.Errorf("the reason must reach the rendered table:\n%s", buf.String())
	}
}

// TestBuildCoverage_CountsManagementSystemApart is the regression for a
// headline that gets more flattering as the honest gap is closed.
//
// ISO 27001 shipped with its 93 Annex A controls and none of the
// clause 4-10 requirements, and this view reported 93 of 93 covered.
// Adding the sixteen missing requirements — with no evidence on file
// for any of them — would, if they were simply folded into the same
// universe, have moved that headline to 109 of 109. The gap closing
// must not read as the gap widening, so the two are counted apart.
func TestBuildCoverage_CountsManagementSystemApart(t *testing.T) {
	v, _ := makeVault(t, []runSeed{{
		framework: frameworkISO27001, periodID: testPeriodQ2, runID: testRunID,
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: testPolicyISOPolicies, Status: core.StatusPass, EvidenceMode: core.EvidenceModeAutomated},
		},
	}})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkISO27001, PeriodID: testPeriodQ2, View: report.ViewCoverage,
		Controls: []core.Control{
			{ID: ctrlA51},
			{ID: ctrlC92, Kind: core.ControlKindManagementSystem},
		},
		Policies: []core.Policy{
			{ID: testPolicyISOPolicies, EvidenceMode: core.EvidenceModeAutomated, Cadence: cadenceDaily,
				Controls: []core.ControlRef{{ControlID: ctrlA51}}},
			{ID: "iso27001.clause.9.2.internal_audit", EvidenceMode: core.EvidenceModeManual, Cadence: cadenceAnnual,
				Controls: []core.ControlRef{{ControlID: ctrlC92}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cov := snap.Coverage
	if cov.Controls != 1 {
		t.Errorf("Controls = %d; want 1 — the management-system requirement is not a catalog control", cov.Controls)
	}
	if cov.ManagementSystem != 1 {
		t.Errorf("ManagementSystem = %d; want 1", cov.ManagementSystem)
	}
	if cov.ManagementSystemOnFile != 0 {
		t.Errorf("ManagementSystemOnFile = %d; want 0 — nothing was uploaded this period", cov.ManagementSystemOnFile)
	}
	if len(cov.Rows) != 2 {
		t.Fatalf("rows = %d; want one per control — the clause requirement is the point of the view, not an appendix", len(cov.Rows))
	}
	if cov.Rows[0].ControlID != ctrlA51 || cov.Rows[0].ManagementSystem {
		t.Errorf("row 0 = %+v; want the catalog control first, unflagged", cov.Rows[0])
	}
	if cov.Rows[1].ControlID != ctrlC92 || !cov.Rows[1].ManagementSystem {
		t.Errorf("row 1 = %+v; want the clause requirement flagged", cov.Rows[1])
	}

	var buf bytes.Buffer
	if err := report.FormatText(&buf, snap); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"1 of 1 catalog controls have a check",
		"1 management-system requirements (counted apart — they are not selectable)",
		"0 with evidence on file this period, 1 without",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("headline missing %q:\n%s", want, buf.String())
		}
	}
}
