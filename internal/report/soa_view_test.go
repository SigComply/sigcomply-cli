package report_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"reflect"
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
		{ID: ctrlA51, Name: "Policies for information security"},
		{ID: ctrlA71, Name: "Physical security perimeters"},
		{ID: ctrlC92, Name: "Internal audit", Kind: core.ControlKindManagementSystem},
	}
	policies := []core.Policy{
		{ID: testPolicyISOPolicies, EvidenceMode: core.EvidenceModeAutomated, Cadence: cadenceDaily,
			Controls: []core.ControlRef{{ControlID: ctrlA51}}},
		{ID: "iso27001.7.1.perimeters", EvidenceMode: core.EvidenceModeManual, Cadence: cadenceAnnual,
			Controls: []core.ControlRef{{ControlID: ctrlA71}}},
		{ID: "iso27001.clause.9.2.internal_audit", EvidenceMode: core.EvidenceModeManual, Cadence: cadenceAnnual,
			Controls: []core.ControlRef{{ControlID: ctrlC92}}},
	}
	return controls, policies
}

func buildSoASnapshot(t *testing.T, controlCfg map[string]spec.ControlConfig) *report.Snapshot {
	t.Helper()
	v, _ := makeVault(t, []runSeed{{
		framework: frameworkISO27001, periodID: testPeriodQ2, runID: testRunID,
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: testPolicyISOPolicies, Status: core.StatusPass, EvidenceMode: core.EvidenceModeAutomated},
		},
	}})
	controls, policies := soaCatalog()
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkISO27001, PeriodID: testPeriodQ2, View: report.ViewSoA,
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
		if v.Rows[i].ControlID == ctrlC92 {
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
		ctrlA71: {Applicability: "not_applicable", Reason: reasonFullyRemote, ApprovedBy: testApprover},
	}).SoA

	if v.Applicable != 1 || v.Excluded != 1 {
		t.Errorf("Applicable/Excluded = %d/%d; want 1/1", v.Applicable, v.Excluded)
	}
	var row *report.SoARow
	for i := range v.Rows {
		if v.Rows[i].ControlID == ctrlA71 {
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
	if row.Justification != reasonFullyRemote {
		t.Errorf("justification = %q; want the operator's own reason verbatim", row.Justification)
	}
	if row.JustificationDerived {
		t.Error("an operator-authored reason must not be marked derived")
	}
	if row.ApprovedBy != testApprover {
		t.Errorf("ApprovedBy = %q; want the recorded approver", row.ApprovedBy)
	}
}

// An operator's own inclusion justification wins; where there is none,
// SigComply derives one and says that it did — so an auditor can tell
// deliberation from boilerplate.
func TestBuildSoA_InclusionJustificationPrefersTheOperator(t *testing.T) {
	v := buildSoASnapshot(t, map[string]spec.ControlConfig{
		ctrlA51: {Applicability: "applicable", Justification: "central to our risk treatment plan"},
	}).SoA

	byID := map[string]report.SoARow{}
	for _, r := range v.Rows {
		byID[r.ControlID] = r
	}
	authored := byID[ctrlA51]
	if authored.Justification != "central to our risk treatment plan" || authored.JustificationDerived {
		t.Errorf("A.5.1 = %q (derived=%v); want the operator's words, not derived",
			authored.Justification, authored.JustificationDerived)
	}
	derived := byID[ctrlA71]
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
	if got := byID[ctrlA51].Status; got != statusImplemented {
		t.Errorf("A.5.1 status = %q; want implemented — its check ran and passed", got)
	}
	if got := byID[ctrlA71].Status; got != statusNotEvaluated {
		t.Errorf("A.7.1 status = %q; want %q — its annual document produced no result this period", got, statusNotEvaluated)
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
		"all pass":             {[]core.PolicyStatus{core.StatusPass, core.StatusPass}, statusImplemented},
		"waived counts as met": {[]core.PolicyStatus{core.StatusPass, core.StatusWaived}, statusImplemented},
		"mixed":                {[]core.PolicyStatus{core.StatusPass, core.StatusFail}, "partially implemented"},
		"all fail":             {[]core.PolicyStatus{core.StatusFail, core.StatusFail}, statusNotImplmntd},
		// A skip is a check that could not run, so on its own it leaves
		// the control with nothing to show for itself.
		"all skip": {[]core.PolicyStatus{core.StatusSkip, core.StatusSkip}, statusNotImplmntd},

		// `na` is a check that never ran: it must not vote either way.
		// Counting it as met turned the documented remedy for a control
		// you cannot satisfy into "implemented" on the one document an
		// auditor reads as an assertion.
		"na alone is not evaluated":       {[]core.PolicyStatus{core.StatusNA}, "not evaluated"},
		"na abstains beside a pass":       {[]core.PolicyStatus{core.StatusPass, core.StatusNA}, statusImplemented},
		"na abstains beside a failure":    {[]core.PolicyStatus{core.StatusFail, core.StatusNA}, statusNotImplmntd},
		"na does not manufacture partial": {[]core.PolicyStatus{core.StatusNA, core.StatusNA}, "not evaluated"},

		// Carry-forward inherits a prior pass — the compliance score and
		// the coverage view both count it as one, and the SoA used to be
		// the only surface calling it statusNotImplmntd.
		"carried forward is a pass":        {[]core.PolicyStatus{core.StatusCarriedForward}, statusImplemented},
		"carried forward beside a pass":    {[]core.PolicyStatus{core.StatusPass, core.StatusCarriedForward}, statusImplemented},
		"carried forward beside a failure": {[]core.PolicyStatus{core.StatusCarriedForward, core.StatusFail}, "partially implemented"},
	} {
		t.Run(name, func(t *testing.T) {
			results := make([]core.PolicyResult, 0, len(tc.statuses))
			policies := make([]core.Policy, 0, len(tc.statuses))
			for i, st := range tc.statuses {
				id := string(rune('a'+i)) + ".policy"
				results = append(results, core.PolicyResult{PolicyID: id, Status: st, EvidenceMode: core.EvidenceModeAutomated})
				policies = append(policies, core.Policy{ID: id, EvidenceMode: core.EvidenceModeAutomated,
					Controls: []core.ControlRef{{ControlID: ctrlA51}}})
			}
			v, _ := makeVault(t, []runSeed{{
				framework: frameworkISO27001, periodID: testPeriodQ2, runID: testRunID,
				timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
				completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
				policies:    results,
			}})
			snap, err := report.Build(context.Background(), &report.Input{
				Vault: v, Framework: frameworkISO27001, PeriodID: testPeriodQ2, View: report.ViewSoA,
				Controls: []core.Control{{ID: ctrlA51, Name: "Policies"}}, Policies: policies,
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
		View: report.ViewSoA, Framework: frameworkISO27001, PeriodID: testPeriodQ2,
		SoA: &report.SoAView{
			Controls: 2, ManagementSystem: 16, Applicable: 1, Excluded: 1,
			Implemented: 1, Derived: 1,
			Note: "16 management-system requirements (clauses 4-10) are outside the Statement of Applicability and cannot be excluded",
			Rows: []report.SoARow{
				{ControlID: ctrlA51, Name: "Policies for information security", Applicable: true,
					Justification:        "Applicable — no exclusion declared. Verified by 1 automated check.",
					JustificationDerived: true, Status: statusImplemented, Assurance: "automated",
					Evaluated: 1, Policies: []string{testPolicyISOPolicies}},
				{ControlID: ctrlA71, Name: "Physical security perimeters", Applicable: false,
					Justification: reasonFullyRemote, Status: "excluded",
					Assurance: assuranceManual, ApprovedBy: testApprover},
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
		ctrlA51, ctrlA71,
		"(derived)",
		reasonFullyRemote,
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
			if err := fn(&buf, &report.Snapshot{View: report.ViewSoA, Framework: frameworkISO27001}); err != nil {
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
	if rows[2][2] != "false" || rows[2][3] != reasonFullyRemote {
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

// buildSoASnapshotWithRisks is buildSoASnapshot plus a declared
// risk→control register.
func buildSoASnapshotWithRisks(t *testing.T, controlCfg map[string]spec.ControlConfig, risks map[string][]string) *report.Snapshot {
	t.Helper()
	v, _ := makeVault(t, []runSeed{{
		framework: frameworkISO27001, periodID: testPeriodQ2, runID: testRunID,
		timestamp:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 4, 1, 0, 5, 0, 0, time.UTC),
		policies: []core.PolicyResult{
			{PolicyID: testPolicyISOPolicies, Status: core.StatusPass, EvidenceMode: core.EvidenceModeAutomated},
		},
	}})
	controls, policies := soaCatalog()
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkISO27001, PeriodID: testPeriodQ2, View: report.ViewSoA,
		Controls: controls, Policies: policies, ControlConfigs: controlCfg,
		ControlRisks: risks,
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

const (
	testRiskID      = "r-001"
	testRiskIDOther = "r-014"
)

func soaRowByID(t *testing.T, snap *report.Snapshot, id string) report.SoARow {
	t.Helper()
	for i := range snap.SoA.Rows {
		if snap.SoA.Rows[i].ControlID == id {
			return snap.SoA.Rows[i]
		}
	}
	t.Fatalf("no SoA row for %s", id)
	return report.SoARow{}
}

// The edge the register exists for: ISO 6.1.3 b) asks for the controls
// "necessary to implement" the chosen treatment, and necessity is a
// claim about a risk. Nothing in the catalog or the vault can say it.
func TestBuildSoA_CitesTheRisksAControlTreats(t *testing.T) {
	snap := buildSoASnapshotWithRisks(t, nil, map[string][]string{ctrlA51: {testRiskID, testRiskIDOther}})
	row := soaRowByID(t, snap, ctrlA51)

	if want := []string{testRiskID, testRiskIDOther}; !reflect.DeepEqual(row.Risks, want) {
		t.Errorf("Risks = %v; want %v", row.Risks, want)
	}
	if !strings.Contains(row.Justification, "Necessary to treat 2 declared risks (r-001, r-014)") {
		t.Errorf("justification = %q; want it to lead with the risks that made the control necessary", row.Justification)
	}
	// The derived detail must survive the new clause, not be replaced by it.
	if !strings.Contains(row.Justification, "automated check") {
		t.Errorf("justification = %q; want the verification detail retained", row.Justification)
	}
	// A control no risk names must stay exactly as it was.
	if other := soaRowByID(t, snap, ctrlA71); len(other.Risks) != 0 {
		t.Errorf("unrelated control carries risks: %v", other.Risks)
	}
}

// An operator who wrote their own justification has already said why the
// control is there. Rewriting their words to append ours would be worse
// than silent — the structured edge is still on the row for every
// renderer.
func TestBuildSoA_RiskCitationNeverRewritesOperatorJustification(t *testing.T) {
	const own = "Required by our customer contracts."
	snap := buildSoASnapshotWithRisks(t,
		map[string]spec.ControlConfig{ctrlA51: {Justification: own}},
		map[string][]string{ctrlA51: {"r-001"}})
	row := soaRowByID(t, snap, ctrlA51)

	if row.Justification != own {
		t.Errorf("justification = %q; want the operator's text verbatim", row.Justification)
	}
	if row.JustificationDerived {
		t.Error("an operator-authored justification must not be flagged derived")
	}
	if !reflect.DeepEqual(row.Risks, []string{testRiskID}) {
		t.Errorf("Risks = %v; the edge must still be carried structurally", row.Risks)
	}
}

// A project with no register must render exactly as it did before one
// existed — no column, no clause, no empty parentheses.
func TestBuildSoA_NoRegisterRendersUnchanged(t *testing.T) {
	withRisks := buildSoASnapshotWithRisks(t, nil, nil)
	plain := buildSoASnapshot(t, nil)

	var a, b strings.Builder
	if err := report.FormatText(&a, withRisks); err != nil {
		t.Fatal(err)
	}
	if err := report.FormatText(&b, plain); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Errorf("a nil register changed the output:\n%s\n---\n%s", a.String(), b.String())
	}
	if strings.Contains(a.String(), "RISKS") {
		t.Error("RISKS column rendered with no register declared")
	}
}

// With a register, the column appears and carries the edge for rows
// whose justification is the operator's own.
func TestFormatTextSoA_ShowsTheRisksColumnWhenDeclared(t *testing.T) {
	snap := buildSoASnapshotWithRisks(t, nil, map[string][]string{ctrlA51: {"r-001"}})
	var out strings.Builder
	if err := report.FormatText(&out, snap); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "RISKS") || !strings.Contains(got, testRiskID) {
		t.Errorf("text output missing the risks column:\n%s", got)
	}
}

// CSV appends risks last, so the existing positional assertions in this
// file keep testing the columns they were written for.
func TestFormatCSVSoA_AppendsRisksLast(t *testing.T) {
	snap := buildSoASnapshotWithRisks(t, nil, map[string][]string{ctrlA51: {testRiskID, testRiskIDOther}})
	var out strings.Builder
	if err := report.FormatCSV(&out, snap); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(out.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	last := len(rows[0]) - 1
	if rows[0][last] != "risks" {
		t.Fatalf("header = %v; want risks appended last", rows[0])
	}
	var found bool
	for _, r := range rows[1:] {
		if r[0] == ctrlA51 {
			found = true
			if r[last] != testRiskID+" r-014" {
				t.Errorf("risks cell = %q; want space-joined ids", r[last])
			}
		}
	}
	if !found {
		t.Errorf("no CSV row for %s", ctrlA51)
	}
}
