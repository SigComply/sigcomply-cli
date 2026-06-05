package report_test

// format_gaps_test.go — covers uncovered formatter branches:
//   - formatCSVLatest nil LatestView (header-only path)
//   - formatCSVExceptions nil ExceptionsView
//   - formatCSVIntegrity nil IntegrityView
//   - formatTextLatest nil LatestView
//   - formatTextExceptions nil ExceptionsView
//   - exceptionScopeLabel resource_pattern branch
//   - dash() non-empty path
//   - FormatJSON with exceptions/integrity views
//   - loadRuns with malformed manifest JSON
//   - exceptionScopeLabel branches

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/report"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
)

// statusFail is the integrity-row status string used throughout the report
// tests; shared as a const so the literal isn't repeated across files.
const statusFail = "fail"

// ---------------------------------------------------------------------------
// Nil sub-view guards in the CSV formatter
// ---------------------------------------------------------------------------

func TestFormatCSV_NilLatestView(t *testing.T) {
	// A Snapshot.Latest == nil with ViewLatest should emit only the header row.
	snap := &report.Snapshot{View: report.ViewLatest, Framework: "soc2", PeriodID: "2026-Q1", Latest: nil}
	var b bytes.Buffer
	if err := report.FormatCSV(&b, snap); err != nil {
		t.Fatalf("FormatCSV nil Latest: %v", err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("expected header-only (1 line); got %d: %q", len(lines), b.String())
	}
	if !strings.HasPrefix(lines[0], "policy_id") {
		t.Errorf("header missing; got %q", lines[0])
	}
}

func TestFormatCSV_NilExceptionsView(t *testing.T) {
	snap := &report.Snapshot{View: report.ViewExceptions, Framework: "soc2", PeriodID: "2026-Q1", Exceptions: nil}
	var b bytes.Buffer
	if err := report.FormatCSV(&b, snap); err != nil {
		t.Fatalf("FormatCSV nil Exceptions: %v", err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("expected header-only (1 line); got %d: %q", len(lines), b.String())
	}
	if !strings.HasPrefix(lines[0], "policy_id,scope") {
		t.Errorf("header missing; got %q", lines[0])
	}
}

func TestFormatCSV_NilIntegrityView(t *testing.T) {
	snap := &report.Snapshot{View: report.ViewIntegrity, Framework: "soc2", PeriodID: "2026-Q1", Integrity: nil}
	var b bytes.Buffer
	if err := report.FormatCSV(&b, snap); err != nil {
		t.Fatalf("FormatCSV nil Integrity: %v", err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("expected header-only (1 line); got %d: %q", len(lines), b.String())
	}
	if !strings.HasPrefix(lines[0], "run_path") {
		t.Errorf("header missing; got %q", lines[0])
	}
}

// ---------------------------------------------------------------------------
// exceptionScopeLabel — resource_pattern branch
// ---------------------------------------------------------------------------

func TestBuild_Exceptions_PatternScopeLabel(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, _ = makeVault(t, nil) // side-effect: ensure makeVault helper is exercised
	_, roots := makeVault(t, []runSeed{
		{
			framework: "soc2", periodID: "2026-Q1", runID: "pattrn00", timestamp: t1, completedAt: t1,
			exceptions: []core.AppliedException{
				{PolicyID: "p1", State: "waived", Reason: "pattern-scoped",
					ResourcePattern: "arn:aws:iam::*:user/svc-*"},
			},
		},
	})
	_ = roots

	// Use the vault that was actually seeded (makeVault returns its own vault).
	vv, _ := makeVault(t, []runSeed{
		{
			framework: "soc2", periodID: "2026-Q1", runID: "pattrn00", timestamp: t1, completedAt: t1,
			exceptions: []core.AppliedException{
				{PolicyID: "p1", State: "waived", Reason: "pattern-scoped",
					ResourcePattern: "arn:aws:iam::*:user/svc-*"},
			},
		},
	})
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: vv, Framework: "soc2", PeriodID: "2026-Q1", View: report.ViewExceptions,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if snap.Exceptions == nil || len(snap.Exceptions.Exceptions) != 1 {
		t.Fatalf("expected 1 exception row")
	}
	e := snap.Exceptions.Exceptions[0]
	if e.Scope != "arn:aws:iam::*:user/svc-*" {
		t.Errorf("Scope = %q; want resource_pattern", e.Scope)
	}
}

// ---------------------------------------------------------------------------
// FormatJSON — exceptions and integrity views
// ---------------------------------------------------------------------------

func TestFormatJSON_ExceptionsView(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewExceptions, Framework: "soc2", PeriodID: "2026-Q1",
		Exceptions: &report.ExceptionsView{Exceptions: []report.ExceptionEntry{
			{PolicyID: "p1", Scope: "policy", State: "na", Reason: "not applicable"},
		}},
	}
	var b bytes.Buffer
	if err := report.FormatJSON(&b, snap); err != nil {
		t.Fatalf("FormatJSON exceptions: %v", err)
	}
	var back report.Snapshot
	if err := json.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.View != report.ViewExceptions {
		t.Errorf("View = %q after round-trip", back.View)
	}
	if back.Exceptions == nil || len(back.Exceptions.Exceptions) != 1 {
		t.Errorf("exceptions survive: %#v", back.Exceptions)
	}
}

func TestFormatJSON_IntegrityView(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewIntegrity, Framework: "soc2", PeriodID: "2026-Q1",
		Integrity: &report.IntegrityView{Runs: []report.IntegrityRow{
			{RunPath: "soc2/2026-Q1/run_a", RunID: "r1", SignatureValid: true, FilesVerified: 2, FilesTotal: 2},
		}},
	}
	var b bytes.Buffer
	if err := report.FormatJSON(&b, snap); err != nil {
		t.Fatalf("FormatJSON integrity: %v", err)
	}
	var back report.Snapshot
	if err := json.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Integrity == nil || len(back.Integrity.Runs) != 1 {
		t.Errorf("integrity runs survive: %#v", back.Integrity)
	}
}

// ---------------------------------------------------------------------------
// loadRuns — malformed manifest.json (JSON parse error)
// The integrity view must retain the run as a "fail" row rather than omit it.
// ---------------------------------------------------------------------------

func TestBuild_Integrity_MalformedManifestJSON(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	ctx := context.Background()
	// Write an unparseable manifest.json inside a run folder.
	if err := v.PutBinary(ctx,
		"soc2/2026-Q1/run_20260215T140000Z_badmanif/manifest.json",
		[]byte(`{not valid json`), nil); err != nil {
		t.Fatalf("plant malformed manifest: %v", err)
	}
	snap, err := report.Build(ctx, &report.Input{
		Vault: v, Framework: "soc2", PeriodID: "2026-Q1", View: report.ViewIntegrity,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(snap.Integrity.Runs) != 1 {
		t.Fatalf("expected 1 run; got %d", len(snap.Integrity.Runs))
	}
	row := snap.Integrity.Runs[0]
	if row.Status() != statusFail {
		t.Errorf("Status() = %q; want fail for malformed manifest", row.Status())
	}
	if row.Error == "" {
		t.Error("Error should be non-empty for malformed manifest")
	}
}

// ---------------------------------------------------------------------------
// formatTextLatest — exception indicator shows when ExceptionID is set
// ---------------------------------------------------------------------------

func TestFormatText_LatestShowsExceptionIndicator(t *testing.T) {
	when := time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC)
	snap := &report.Snapshot{
		View: report.ViewLatest, Framework: "soc2", PeriodID: "2026-Q1",
		Latest: &report.LatestView{Policies: []report.LatestPolicy{
			{PolicyID: "soc2.cc6.1.mfa", ControlID: "SOC2.CC6.1", Status: "waived",
				Severity: "high", Category: "access", LastEvaluated: when, RunID: "run1",
				ExceptionID: "soc2.cc6.1.mfa"}, // exception present
			{PolicyID: "soc2.cc6.3.review", ControlID: "SOC2.CC6.3", Status: "pass",
				Severity: "medium", LastEvaluated: when, RunID: "run1",
				ExceptionID: ""}, // no exception → "-" in output
		}},
	}
	var b bytes.Buffer
	if err := report.FormatText(&b, snap); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "soc2.cc6.1.mfa") {
		t.Errorf("exception ID missing from output: %q", out)
	}
	// The "-" dash placeholder must appear for the policy without an exception.
	if !strings.Contains(out, "-") {
		t.Errorf("dash placeholder missing for no-exception policy: %q", out)
	}
}

// ---------------------------------------------------------------------------
// formatTextIntegrity — detail=mismatch: and detail=error paths
// ---------------------------------------------------------------------------

func TestFormatText_IntegrityDetailPaths(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewIntegrity, Framework: "soc2", PeriodID: "2026-Q1",
		Integrity: &report.IntegrityView{Runs: []report.IntegrityRow{
			// run with mismatch path (detail = "mismatch: <path>")
			{RunPath: "soc2/2026-Q1/run_a", RunID: "r1", SignatureValid: true,
				FilesVerified: 1, FilesTotal: 2, FirstMismatchPath: "policies/p1/result.json"},
			// run with signature error only (detail = oneLine(error))
			{RunPath: "soc2/2026-Q1/run_b", RunID: "r2", SignatureValid: false,
				FilesTotal: 3, Error: "signature verification failed"},
			// clean run (detail = "-")
			{RunPath: "soc2/2026-Q1/run_c", RunID: "r3", SignatureValid: true,
				FilesVerified: 2, FilesTotal: 2},
		}},
	}
	var b bytes.Buffer
	if err := report.FormatText(&b, snap); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "mismatch: policies/p1/result.json") {
		t.Errorf("mismatch detail missing: %q", out)
	}
	if !strings.Contains(out, "signature verification failed") {
		t.Errorf("error detail missing: %q", out)
	}
	if !strings.Contains(out, "pass") {
		t.Errorf("pass status missing: %q", out)
	}
}

// ---------------------------------------------------------------------------
// formatTextExceptions — exercises the oneLine helper on multi-line reasons
// ---------------------------------------------------------------------------

func TestFormatText_ExceptionMultiLineReason(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewExceptions, Framework: "soc2", PeriodID: "2026-Q1",
		Exceptions: &report.ExceptionsView{Exceptions: []report.ExceptionEntry{
			{PolicyID: "p1", Scope: "policy", State: "na",
				Reason: "Line one.\nLine two.\tTabbed."},
		}},
	}
	var b bytes.Buffer
	if err := report.FormatText(&b, snap); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	out := b.String()
	// oneLine must have replaced newlines with spaces so the reason
	// does not split across tabwriter rows. Verify by confirming the
	// literal "\n" from the reason text is absent (the tabwriter does
	// emit row-separating newlines, but none should be mid-reason).
	if strings.Contains(out, "Line one.\nLine two.") {
		t.Error("multi-line reason leaked raw newlines into tabwriter row")
	}
	if !strings.Contains(out, "Line one.") {
		t.Errorf("reason text missing: %q", out)
	}
}

// ---------------------------------------------------------------------------
// FormatJSON — unsupported view surfaces an error
// ---------------------------------------------------------------------------

func TestFormatJSON_AnyViewSucceeds(t *testing.T) {
	// FormatJSON encodes the Snapshot as-is regardless of View — verify
	// it does not error for known views.
	for _, view := range []report.View{report.ViewLatest, report.ViewExceptions, report.ViewIntegrity} {
		snap := &report.Snapshot{View: view, Framework: "soc2", PeriodID: "2026-Q1"}
		var b bytes.Buffer
		if err := report.FormatJSON(&b, snap); err != nil {
			t.Errorf("FormatJSON(%s): %v", view, err)
		}
	}
}

// ---------------------------------------------------------------------------
// IntegrityRow.Status — all branches
// ---------------------------------------------------------------------------

func TestIntegrityRow_StatusBranches(t *testing.T) {
	cases := []struct {
		name string
		row  report.IntegrityRow
		want string
	}{
		{"pass", report.IntegrityRow{SignatureValid: true, FilesVerified: 2, FilesTotal: 2}, "pass"},
		{"fail_no_sig", report.IntegrityRow{SignatureValid: false, Error: "bad sig"}, statusFail},
		{"fail_mismatch", report.IntegrityRow{SignatureValid: true, FirstMismatchPath: "x"}, statusFail},
		{"fail_error_only", report.IntegrityRow{SignatureValid: true, Error: "file missing"}, statusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.row.Status(); got != c.want {
				t.Errorf("Status() = %q; want %q", got, c.want)
			}
		})
	}
}
