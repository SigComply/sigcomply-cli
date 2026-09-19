package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/report"
)

// A run written before scope existed has no block in summary.json. The
// view must still render, and must still show the skipped controls —
// that half is what a green run hides regardless of any declaration.
func TestFormatTextScope_UndeclaredStillShowsSkips(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewScope, Framework: frameworkSOC2, PeriodID: testPeriodQ1,
		Scope: &report.ScopeView{
			Declared: false,
			Skipped: []report.SkippedPolicy{
				{PolicyID: testPolicyMFA, Status: "skip", Reason: reasonNoRecords},
			},
		},
	}
	var buf bytes.Buffer
	if err := report.FormatText(&buf, snap); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Declared estate: none") {
		t.Errorf("missing undeclared line:\n%s", out)
	}
	if !strings.Contains(out, testPolicyMFA) || !strings.Contains(out, "excluded from the compliance score") {
		t.Errorf("skipped controls not surfaced:\n%s", out)
	}
}

func TestFormatTextScope_DeclaredRendersSourcesAndVerdict(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewScope, Framework: frameworkSOC2, PeriodID: testPeriodQ1,
		Scope: &report.ScopeView{
			Declared: true, Status: statusIncomplete,
			DeclaredBy: testApprover, DeclaredAt: "2026-09-13",
			Sources: []report.ScopeSource{
				{SourceID: "github", State: "ok"},
				{SourceID: testSourceOkta, State: stateNotConfigured},
			},
		},
	}
	var buf bytes.Buffer
	if err := report.FormatText(&buf, snap); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{statusIncomplete, testApprover, testSourceOkta, stateNotConfigured, "Every control in the latest run was evaluated."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatCSVScope_RowsAndHeader(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewScope, Framework: frameworkSOC2, PeriodID: testPeriodQ1,
		Scope: &report.ScopeView{
			Declared: true, Status: statusIncomplete, RunID: "r1",
			Sources: []report.ScopeSource{{SourceID: testSourceOkta, State: stateNotConfigured}},
			Skipped: []report.SkippedPolicy{{PolicyID: "p1", Status: "skip", Reason: reasonNoRecords}},
		},
	}
	var buf bytes.Buffer
	if err := report.FormatCSV(&buf, snap); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows; got %d lines:\n%s", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], "kind,id,state_or_reason") {
		t.Errorf("unexpected header: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "declared_source,okta,not_configured") {
		t.Errorf("unexpected source row: %s", lines[1])
	}
	if !strings.HasPrefix(lines[2], "skipped_policy,p1,") {
		t.Errorf("unexpected skip row: %s", lines[2])
	}
}

func TestFormatScope_NilViewDoesNotPanic(t *testing.T) {
	snap := &report.Snapshot{View: report.ViewScope, Framework: frameworkSOC2, PeriodID: testPeriodQ1}
	var text, csv bytes.Buffer
	if err := report.FormatText(&text, snap); err != nil {
		t.Fatal(err)
	}
	if err := report.FormatCSV(&csv, snap); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "no runs") {
		t.Errorf("text = %q", text.String())
	}
}

// Auditors diff runs, so repeated formatting must be byte-identical.
func TestFormatTextScope_Deterministic(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewScope, Framework: frameworkSOC2, PeriodID: testPeriodQ1,
		Scope: &report.ScopeView{
			Declared: true, Status: statusIncomplete,
			Sources: []report.ScopeSource{{SourceID: "a", State: "ok"}, {SourceID: "b", State: "no_records"}},
			Skipped: []report.SkippedPolicy{{PolicyID: "p1", Reason: "x"}, {PolicyID: "p2", Reason: "y"}},
		},
	}
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
			t.Fatal("scope view output is not deterministic")
		}
	}
}
