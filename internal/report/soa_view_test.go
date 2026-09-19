package report_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/report"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// soaCatalog is a miniature ISO-shaped framework: two Annex A controls
// and one management-system clause.
func soaCatalog() ([]core.Control, []core.Policy) {
	controls := []core.Control{
		{ID: "A.5.1", Name: "Policies for information security"},
		{ID: "A.7.1", Name: "Physical security perimeters"},
		{ID: "C.9.2", Name: "Internal audit", Kind: core.ControlKindManagementSystem},
	}
	policies := []core.Policy{
		{ID: "iso27001.5.1.policies", EvidenceMode: core.EvidenceModeAutomated, Cadence: "daily",
			Controls: []core.ControlRef{{ControlID: "A.5.1"}}},
		{ID: "iso27001.7.1.perimeters", EvidenceMode: core.EvidenceModeManual, Cadence: "annual",
			Controls: []core.ControlRef{{ControlID: "A.7.1"}}},
		{ID: "iso27001.clause.9.2.internal_audit", EvidenceMode: core.EvidenceModeManual, Cadence: "annual",
			Controls: []core.ControlRef{{ControlID: "C.9.2"}}},
	}
	return controls, policies
}

func buildSoASnapshot(t *testing.T, controlCfg map[string]spec.ControlConfig) *report.Snapshot {
	t.Helper()
	v, _ := makeVault(t, []runSeed{{
		framework: "iso27001", periodID: "2026-Q2", runID: "run-aaaa",
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: "iso27001.5.1.policies", Status: core.StatusPass, EvidenceMode: core.EvidenceModeAutomated},
		},
	}})
	controls, policies := soaCatalog()
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: "iso27001", PeriodID: "2026-Q2", View: report.ViewSoA,
		Controls: controls, Policies: policies, ControlConfigs: controlCfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// TestBuildSoA_OmitsManagementSystemRequirements is the load-bearing
// one. A Statement of Applicability is a table of include/exclude
// decisions over the control catalog; ISO's clauses 4-10 are not
// selectable, and listing them would invite an exclusion the standard
// does not permit.
func TestBuildSoA_OmitsManagementSystemRequirements(t *testing.T) {
	v := buildSoASnapshot(t, nil).SoA
	if v.Controls != 2 {
		t.Errorf("Controls = %d; want 2 catalog controls", v.Controls)
	}
	if v.ManagementSystem != 1 {
		t.Errorf("ManagementSystem = %d; want 1 counted but not listed", v.ManagementSystem)
	}
	for i := range v.Rows {
		if v.Rows[i].ControlID == "C.9.2" {
			t.Error("a management-system requirement must never appear as a SoA row")
		}
	}
	if !strings.Contains(v.Note, "cannot be excluded") {
		t.Errorf("note = %q; want it to say why the clauses are absent", v.Note)
	}
}

// TestBuildSoA_ExclusionCarriesTheOperatorsReason: the fourth thing
// 6.1.3 d asks for is the justification for leaving a control out, and
// it must be the operator's words, not ours.
func TestBuildSoA_ExclusionCarriesTheOperatorsReason(t *testing.T) {
	v := buildSoASnapshot(t, map[string]spec.ControlConfig{
		"A.7.1": {Applicability: "not_applicable", Reason: "fully remote; no premises in scope", ApprovedBy: "ciso@example.com"},
	}).SoA

	if v.Applicable != 1 || v.Excluded != 1 {
		t.Errorf("Applicable/Excluded = %d/%d; want 1/1", v.Applicable, v.Excluded)
	}
	var row *report.SoARow
	for i := range v.Rows {
		if v.Rows[i].ControlID == "A.7.1" {
			row = &v.Rows[i]
		}
	}
	if row == nil {
		t.Fatal("A.7.1 is missing from the SoA")
	}
	if row.Applicable {
		t.Error("A.7.1 is declared not_applicable and must report as excluded")
	}
	if row.Status != "excluded" {
		t.Errorf("status = %q; want excluded", row.Status)
	}
	if row.Justification != "fully remote; no premises in scope" {
		t.Errorf("justification = %q; want the operator's own reason verbatim", row.Justification)
	}
	if row.JustificationDerived {
		t.Error("an operator-authored reason must not be marked derived")
	}
	if row.ApprovedBy != "ciso@example.com" {
		t.Errorf("ApprovedBy = %q; want the recorded approver", row.ApprovedBy)
	}
}

// An operator's own inclusion justification wins; where there is none,
// SigComply derives one and says that it did — so an auditor can tell
// deliberation from boilerplate.
func TestBuildSoA_InclusionJustificationPrefersTheOperator(t *testing.T) {
	v := buildSoASnapshot(t, map[string]spec.ControlConfig{
		"A.5.1": {Applicability: "applicable", Justification: "central to our risk treatment plan"},
	}).SoA

	byID := map[string]report.SoARow{}
	for _, r := range v.Rows {
		byID[r.ControlID] = r
	}
	authored := byID["A.5.1"]
	if authored.Justification != "central to our risk treatment plan" || authored.JustificationDerived {
		t.Errorf("A.5.1 = %q (derived=%v); want the operator's words, not derived",
			authored.Justification, authored.JustificationDerived)
	}
	derived := byID["A.7.1"]
	if !derived.JustificationDerived {
		t.Error("A.7.1 has no authored justification and must be marked derived")
	}
	if !strings.Contains(derived.Justification, "manual evidence item") {
		t.Errorf("derived justification = %q; want it to name the checks behind the control", derived.Justification)
	}
	if v.Derived != 1 {
		t.Errorf("Derived = %d; want 1", v.Derived)
	}
	if !strings.Contains(v.Note, "derived justification") {
		t.Errorf("note = %q; want it to point at controls.<id>.justification", v.Note)
	}
}

// Status is derived from the period's results and never borrowed from
// the catalog: a control whose checks did not run is unevaluated, not
// implemented. Reporting the latter is the whole failure mode a
// Statement of Applicability is read to catch.
func TestBuildSoA_UnevaluatedIsNotImplemented(t *testing.T) {
	v := buildSoASnapshot(t, nil).SoA

	byID := map[string]report.SoARow{}
	for _, r := range v.Rows {
		byID[r.ControlID] = r
	}
	if got := byID["A.5.1"].Status; got != "implemented" {
		t.Errorf("A.5.1 status = %q; want implemented — its check ran and passed", got)
	}
	if got := byID["A.7.1"].Status; got != "not evaluated" {
		t.Errorf("A.7.1 status = %q; want %q — its annual document produced no result this period", got, "not evaluated")
	}
	if v.Implemented != 1 || v.NotEvaluated != 1 {
		t.Errorf("Implemented/NotEvaluated = %d/%d; want 1/1", v.Implemented, v.NotEvaluated)
	}
	if !strings.Contains(v.Note, "not evaluated is not implemented") {
		t.Errorf("note = %q; want it to say so in words", v.Note)
	}
}

func TestBuildSoA_StatusRollup(t *testing.T) {
	for name, tc := range map[string]struct {
		statuses []core.PolicyStatus
		want     string
	}{
		"all pass":             {[]core.PolicyStatus{core.StatusPass, core.StatusPass}, "implemented"},
		"waived counts as met": {[]core.PolicyStatus{core.StatusPass, core.StatusWaived}, "implemented"},
		"mixed":                {[]core.PolicyStatus{core.StatusPass, core.StatusFail}, "partially implemented"},
		"all fail":             {[]core.PolicyStatus{core.StatusFail, core.StatusFail}, "not implemented"},
	} {
		t.Run(name, func(t *testing.T) {
			results := make([]core.PolicyResult, 0, len(tc.statuses))
			policies := make([]core.Policy, 0, len(tc.statuses))
			for i, st := range tc.statuses {
				id := string(rune('a'+i)) + ".policy"
				results = append(results, core.PolicyResult{PolicyID: id, Status: st, EvidenceMode: core.EvidenceModeAutomated})
				policies = append(policies, core.Policy{ID: id, EvidenceMode: core.EvidenceModeAutomated,
					Controls: []core.ControlRef{{ControlID: "A.5.1"}}})
			}
			v, _ := makeVault(t, []runSeed{{
				framework: "iso27001", periodID: "2026-Q2", runID: "run-aaaa",
				timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
				completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
				policies:    results,
			}})
			snap, err := report.Build(context.Background(), &report.Input{
				Vault: v, Framework: "iso27001", PeriodID: "2026-Q2", View: report.ViewSoA,
				Controls: []core.Control{{ID: "A.5.1", Name: "Policies"}}, Policies: policies,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := snap.SoA.Rows[0].Status; got != tc.want {
				t.Errorf("status = %q; want %q", got, tc.want)
			}
		})
	}
}

func soaSnapshot() *report.Snapshot {
	return &report.Snapshot{
		View: report.ViewSoA, Framework: "iso27001", PeriodID: "2026-Q2",
		SoA: &report.SoAView{
			Controls: 2, ManagementSystem: 16, Applicable: 1, Excluded: 1,
			Implemented: 1, Derived: 1,
			Note: "16 management-system requirements (clauses 4-10) are outside the Statement of Applicability and cannot be excluded",
			Rows: []report.SoARow{
				{ControlID: "A.5.1", Name: "Policies for information security", Applicable: true,
					Justification:        "Applicable — no exclusion declared. Verified by 1 automated check.",
					JustificationDerived: true, Status: "implemented", Assurance: "automated",
					Evaluated: 1, Policies: []string{"iso27001.5.1.policies"}},
				{ControlID: "A.7.1", Name: "Physical security perimeters", Applicable: false,
					Justification: "fully remote; no premises in scope", Status: "excluded",
					Assurance: "manual", ApprovedBy: "ciso@example.com"},
			},
		},
	}
}

func TestFormatTextSoA_ShowsTheFourThingsISORequires(t *testing.T) {
	var buf bytes.Buffer
	if err := report.FormatText(&buf, soaSnapshot()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"2 catalog controls: 1 applicable, 1 excluded",
		"1 implemented",
		"A.5.1", "A.7.1",
		"(derived)",
		"fully remote; no premises in scope",
		"cannot be excluded",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatSoA_NilViewDoesNotPanic(t *testing.T) {
	for name, fn := range map[string]func(*bytes.Buffer, *report.Snapshot) error{
		"text": func(b *bytes.Buffer, s *report.Snapshot) error { return report.FormatText(b, s) },
		"json": func(b *bytes.Buffer, s *report.Snapshot) error { return report.FormatJSON(b, s) },
		"csv":  func(b *bytes.Buffer, s *report.Snapshot) error { return report.FormatCSV(b, s) },
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := fn(&buf, &report.Snapshot{View: report.ViewSoA, Framework: "iso27001"}); err != nil {
				t.Fatalf("nil SoA view: %v", err)
			}
		})
	}
}

// A nil view must still yield a well-formed, header-only file — an
// empty CSV that a spreadsheet refuses to open is a worse answer than
// one with no rows.
func TestFormatCSV_NilSoAViewEmitsHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := report.FormatCSV(&buf, &report.Snapshot{View: report.ViewSoA}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("not well-formed CSV: %v", err)
	}
	if len(rows) != 1 || rows[0][0] != "control_id" {
		t.Errorf("rows = %v; want exactly the header", rows)
	}
}

func TestFormatCSVSoA_CarriesJustificationAndStatus(t *testing.T) {
	var buf bytes.Buffer
	if err := report.FormatCSV(&buf, soaSnapshot()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows; want header + 2 controls", len(rows))
	}
	header := strings.Join(rows[0], ",")
	for _, want := range []string{"applicable", "justification", "justification_derived", "status"} {
		if !strings.Contains(header, want) {
			t.Errorf("header %q is missing %q", header, want)
		}
	}
	if rows[2][2] != "false" || rows[2][3] != "fully remote; no premises in scope" {
		t.Errorf("excluded row = %v; want applicable=false with the operator's reason", rows[2])
	}
}

// Determinism is a hard requirement of the package: an auditor
// re-running a report must get byte-identical output.
func TestFormatSoA_Deterministic(t *testing.T) {
	var first bytes.Buffer
	if err := report.FormatText(&first, soaSnapshot()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		var buf bytes.Buffer
		if err := report.FormatText(&buf, soaSnapshot()); err != nil {
			t.Fatal(err)
		}
		if buf.String() != first.String() {
			t.Fatal("SoA text output is not deterministic across renders")
		}
	}
}
