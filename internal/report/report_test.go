package report_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/report"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
)

// Fixture values shared by the package's report tests. Repeated
// literals live here so a period, control or policy ID is spelled
// once; statusFail is declared alongside its siblings in
// format_gaps_test.go.
const (
	// Audit periods the seeded runs are written into.
	testPeriodQ1 = "2026-Q1"
	testPeriodQ2 = "2026-Q2"

	frameworkSOC2     = "soc2"
	frameworkISO27001 = "iso27001"

	// Statuses and states as they appear in rendered output.
	statusPass         = "pass"
	statusWaived       = "waived"
	statusIncomplete   = "incomplete"
	statusImplemented  = "implemented"
	statusNotEvaluated = "not evaluated"
	stateNotConfigured = "not_configured"

	// Exception scopes: whole-policy, a single resource, a pattern.
	scopePolicy          = "policy"
	scopeLegacyIAMUser   = "iam_user_legacy"
	scopeServiceUserARNs = "arn:aws:iam::*:user/svc-*"

	// Exception approval metadata.
	testApprovedAt = "2026-01-15"
	testExpiresAt  = "2026-07-15"
	testApprover   = "ciso@example.com"

	// Policies under test and their categories.
	testPolicyMFA          = "soc2.cc6.1.mfa"
	testPolicyAccessReview = "soc2.cc6.3.review"
	testPolicyISOPolicies  = "iso27001.5.1.policies"
	testCategoryAccess     = "access"

	// Controls: SOC 2 criteria, ISO 27001 Annex A, ISO clause.
	ctrlCC11     = "CC1.1"
	ctrlCC61     = "CC6.1"
	ctrlSOC2CC61 = "SOC2.CC6.1"
	ctrlA51      = "A.5.1"
	ctrlA71      = "A.7.1"
	ctrlC92      = "C.9.2"

	cadenceDaily  = "daily"
	cadenceAnnual = "annual"

	assuranceManual = "manual"

	testRunID       = "run-aaaa"
	testRunPathA    = "soc2/2026-Q1/run_a"
	summaryFileName = "summary.json"

	testSourceOkta = "okta"

	// Reasons carried through from evaluation diagnostics and from
	// the project config's applicability decisions.
	reasonNoRecords    = "required slot has no records"
	reasonAccessDenied = "aws.iam: access denied"
	reasonFullyRemote  = "fully remote; no premises in scope"
)

// runSeed describes a single run we want to materialize into the test
// vault. The helper writes a per-run manifest (signed) plus one
// result.json per policy. Keeping the helper here (rather than
// shared) makes each test self-documenting.
type runSeed struct {
	framework   string
	periodID    string
	runID       string
	timestamp   time.Time
	completedAt time.Time
	policies    []core.PolicyResult
	exceptions  []core.AppliedException
	// extraFiles, when non-nil, lets a test inject additional files
	// (e.g. summary.json) into the run folder. The map's bytes are
	// also recorded in manifest.file_hashes so the integrity view sees
	// them.
	extraFiles map[string][]byte
}

// makeVault seeds a local-filesystem vault rooted at a fresh TempDir
// with the supplied runs. Returns the vault for direct use by the
// caller and the runRoot paths in the order seeds were given.
func makeVault(t *testing.T, seeds []runSeed) (vault core.Vault, runRoots []string) {
	t.Helper()
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("vault.Init: %v", err)
	}
	roots := make([]string, 0, len(seeds))
	for i := range seeds {
		root := seedRun(t, v, &seeds[i])
		roots = append(roots, root)
	}
	return v, roots
}

func seedRun(t *testing.T, v core.Vault, s *runSeed) string {
	t.Helper()
	ctx := context.Background()
	stamp := s.timestamp.UTC().Format("20060102T150405Z")
	short := s.runID
	if len(short) > 8 {
		short = short[:8]
	}
	runRoot := s.framework + "/" + s.periodID + "/run_" + stamp + "_" + short

	// Build a recording-style hash table as we write each file so the
	// manifest can reference them and the integrity view can verify.
	fileHashes := map[string]string{}

	for i := range s.policies {
		p := &s.policies[i]
		key := runRoot + "/policies/" + p.PolicyID + "/result.json"
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal policy result: %v", err)
		}
		if err := v.PutBinary(ctx, key, data, nil); err != nil {
			t.Fatalf("write result.json: %v", err)
		}
		fileHashes[hashKey(runRoot, key)] = hashSHA256(data)
	}
	for name, body := range s.extraFiles {
		key := runRoot + "/" + name
		if err := v.PutBinary(ctx, key, body, nil); err != nil {
			t.Fatalf("write extra %s: %v", name, err)
		}
		fileHashes[name] = hashSHA256(body)
	}

	manifest := &core.Manifest{
		SchemaVersion:     "run.v1",
		RunID:             s.runID,
		Framework:         s.framework,
		PeriodID:          s.periodID,
		StartedAt:         s.timestamp,
		CompletedAt:       s.completedAt,
		FileHashes:        fileHashes,
		ExceptionsApplied: s.exceptions,
	}
	if err := sign.Manifest(manifest); err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := v.PutJSON(ctx, runRoot+"/manifest.json", manifest); err != nil {
		t.Fatalf("write manifest.json: %v", err)
	}
	return runRoot
}

func hashKey(runRoot, fullKey string) string {
	return strings.TrimPrefix(fullKey, runRoot+"/")
}

func hashSHA256(b []byte) string {
	// Use the same sha256 prefix the orchestrator stamps so the
	// integrity view's recomputed hashes match.
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// TestBuild_Latest_LatestWinsAcrossRuns confirms that when a policy
// appears in multiple runs, the row in the latest view reflects the
// later run's result.
func TestBuild_Latest_LatestWinsAcrossRuns(t *testing.T) {
	earlier := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)
	later := time.Date(2026, 2, 16, 10, 0, 0, 0, time.UTC)

	v, _ := makeVault(t, []runSeed{
		{
			framework: frameworkSOC2, periodID: testPeriodQ1,
			runID: "earlierr", timestamp: earlier, completedAt: earlier,
			policies: []core.PolicyResult{
				{PolicyID: testPolicyMFA, Controls: []core.ControlRef{{ControlID: ctrlSOC2CC61}}, Status: core.StatusFail, Severity: core.SeverityHigh, Category: testCategoryAccess},
			},
		},
		{
			framework: frameworkSOC2, periodID: testPeriodQ1,
			runID: "laterr00", timestamp: later, completedAt: later,
			policies: []core.PolicyResult{
				{PolicyID: testPolicyMFA, Controls: []core.ControlRef{{ControlID: ctrlSOC2CC61}}, Status: core.StatusPass, Severity: core.SeverityHigh, Category: testCategoryAccess},
			},
		},
	})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewLatest,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if snap.Latest == nil || len(snap.Latest.Policies) != 1 {
		t.Fatalf("Latest.Policies = %#v", snap.Latest)
	}
	got := snap.Latest.Policies[0]
	if got.Status != statusPass {
		t.Errorf("Status = %q; want pass (latest run wins)", got.Status)
	}
	if got.RunID != "laterr00" {
		t.Errorf("RunID = %q; want laterr00", got.RunID)
	}
}

// TestBuild_Latest_EmptyPeriodIsNotAnError documents that a period
// with no runs produces a Snapshot whose Latest.Policies is empty —
// not a Build error. Auditors querying a brand-new period should see
// "no data" rather than a stack trace.
func TestBuild_Latest_EmptyPeriodIsNotAnError(t *testing.T) {
	v, _ := makeVault(t, nil)
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewLatest,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if snap.Latest == nil || len(snap.Latest.Policies) != 0 {
		t.Errorf("expected empty latest view; got %#v", snap.Latest)
	}
}

// TestBuild_Exceptions_DedupedAcrossRuns confirms that a single waiver
// declared in two runs appears once in the register, with FirstSeen/
// LastSeen pinned to the appropriate runs.
func TestBuild_Exceptions_DedupedAcrossRuns(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 2, 20, 0, 0, 0, 0, time.UTC)

	exc := core.AppliedException{
		PolicyID:   testPolicyMFA,
		State:      statusWaived,
		ResourceID: scopeLegacyIAMUser,
		Reason:     "Service account; rotation in progress",
		ApprovedBy: "jane@acme.com",
		ApprovedAt: testApprovedAt,
		ExpiresAt:  testExpiresAt,
	}
	v, _ := makeVault(t, []runSeed{
		{framework: frameworkSOC2, periodID: testPeriodQ1, runID: "first000", timestamp: t1, completedAt: t1, exceptions: []core.AppliedException{exc}},
		{framework: frameworkSOC2, periodID: testPeriodQ1, runID: "mid00000", timestamp: t2, completedAt: t2, exceptions: []core.AppliedException{exc}},
		{framework: frameworkSOC2, periodID: testPeriodQ1, runID: "lastrr00", timestamp: t3, completedAt: t3, exceptions: []core.AppliedException{exc}},
	})

	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewExceptions,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if snap.Exceptions == nil || len(snap.Exceptions.Exceptions) != 1 {
		t.Fatalf("Exceptions = %#v; want exactly one row after dedup", snap.Exceptions)
	}
	e := snap.Exceptions.Exceptions[0]
	if e.FirstSeenRunID != "first000" || e.LastSeenRunID != "lastrr00" {
		t.Errorf("FirstSeen=%q LastSeen=%q; want first000/lastrr00", e.FirstSeenRunID, e.LastSeenRunID)
	}
	if e.Scope != scopeLegacyIAMUser {
		t.Errorf("Scope = %q; want iam_user_legacy", e.Scope)
	}
	if e.State != statusWaived || e.ApprovedBy != "jane@acme.com" {
		t.Errorf("waiver shape lost: %#v", e)
	}
}

// TestBuild_Exceptions_PolicyScopeLabel confirms that a whole-policy
// waiver (no resource_id / pattern) renders Scope = "policy".
func TestBuild_Exceptions_PolicyScopeLabel(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v, _ := makeVault(t, []runSeed{
		{framework: frameworkSOC2, periodID: testPeriodQ1, runID: "rrunaaaa", timestamp: t1, completedAt: t1, exceptions: []core.AppliedException{
			{PolicyID: testPolicyAccessReview, State: "na", Reason: "Out of scope"},
		}},
	})
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewExceptions,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if snap.Exceptions.Exceptions[0].Scope != scopePolicy {
		t.Errorf("Scope = %q; want \"policy\"", snap.Exceptions.Exceptions[0].Scope)
	}
}

// TestBuild_Integrity_PassesOnUnmodifiedRun verifies that an
// untampered run passes the integrity check end-to-end (signature
// valid, every file_hashes entry matches recomputed SHA-256).
func TestBuild_Integrity_PassesOnUnmodifiedRun(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v, _ := makeVault(t, []runSeed{
		{
			framework: frameworkSOC2, periodID: testPeriodQ1, runID: "intg0000",
			timestamp: t1, completedAt: t1,
			policies: []core.PolicyResult{
				{PolicyID: "p1", Controls: []core.ControlRef{{ControlID: "C1"}}, Status: core.StatusPass},
			},
			extraFiles: map[string][]byte{summaryFileName: []byte(`{"ok":true}`)},
		},
	})
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewIntegrity,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(snap.Integrity.Runs) != 1 {
		t.Fatalf("Integrity.Runs len = %d", len(snap.Integrity.Runs))
	}
	row := snap.Integrity.Runs[0]
	if row.Status() != statusPass {
		t.Errorf("Status() = %q; want pass — err=%q firstMismatch=%q", row.Status(), row.Error, row.FirstMismatchPath)
	}
	if row.FilesVerified != row.FilesTotal {
		t.Errorf("verified %d of %d", row.FilesVerified, row.FilesTotal)
	}
}

// TestBuild_Integrity_DetectsTamperedFile flips the bytes of a written
// summary.json and confirms the integrity view reports the path of
// the first mismatch.
func TestBuild_Integrity_DetectsTamperedFile(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v, roots := makeVault(t, []runSeed{
		{
			framework: frameworkSOC2, periodID: testPeriodQ1, runID: "tampered",
			timestamp: t1, completedAt: t1,
			extraFiles: map[string][]byte{summaryFileName: []byte(`{"ok":true}`)},
		},
	})
	// Overwrite summary.json with new bytes — this changes its SHA-256
	// but leaves the manifest's recorded hash untouched, simulating
	// post-write tampering.
	if err := v.PutBinary(context.Background(), roots[0]+"/summary.json", []byte(`{"ok":false}`), nil); err != nil {
		t.Fatalf("tamper write: %v", err)
	}
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewIntegrity,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	row := snap.Integrity.Runs[0]
	if row.Status() != statusFail {
		t.Errorf("Status() = %q; want fail (file was tampered)", row.Status())
	}
	if row.FirstMismatchPath != summaryFileName {
		t.Errorf("FirstMismatchPath = %q; want summary.json", row.FirstMismatchPath)
	}
}

// TestBuild_RejectsUnknownView surfaces ErrUnknownView with the
// passed-in name in the message, so the CLI command can echo it back.
func TestBuild_RejectsUnknownView(t *testing.T) {
	v, _ := makeVault(t, nil)
	_, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: "made-up",
	})
	if err == nil {
		t.Fatal("want error on unknown view")
	}
	if !strings.Contains(err.Error(), "made-up") {
		t.Errorf("err should name the bad view; got %v", err)
	}
}

// TestBuild_RejectsBadInputs covers the validation branch.
func TestBuild_RejectsBadInputs(t *testing.T) {
	if _, err := report.Build(context.Background(), nil); err == nil {
		t.Error("Build(nil) = nil; want error")
	}
	v, _ := makeVault(t, nil)
	if _, err := report.Build(context.Background(), &report.Input{Framework: frameworkSOC2, PeriodID: testPeriodQ1}); err == nil {
		t.Error("Build without Vault = nil; want error")
	}
	if _, err := report.Build(context.Background(), &report.Input{Vault: v, PeriodID: testPeriodQ1}); err == nil {
		t.Error("Build without Framework = nil; want error")
	}
	if _, err := report.Build(context.Background(), &report.Input{Vault: v, Framework: frameworkSOC2}); err == nil {
		t.Error("Build without PeriodID = nil; want error")
	}
}

// TestFormatText_LatestDeterministic re-runs the formatter twice and
// confirms byte-identical output. The header is part of the body but
// contains no timestamp, so equal Snapshots → equal bytes.
func TestFormatText_LatestDeterministic(t *testing.T) {
	snap := sampleLatestSnapshot()
	var a, b bytes.Buffer
	if err := report.FormatText(&a, snap); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	if err := report.FormatText(&b, snap); err != nil {
		t.Fatalf("FormatText (2): %v", err)
	}
	if a.String() != b.String() {
		t.Errorf("non-deterministic text output:\nA:\n%s\nB:\n%s", a.String(), b.String())
	}
	if !strings.Contains(a.String(), "POLICY_ID") {
		t.Errorf("header missing; got %q", a.String())
	}
}

// TestFormatJSON_RoundTripsSnapshot confirms the JSON form is
// parseable and the policies survive a round-trip.
func TestFormatJSON_RoundTripsSnapshot(t *testing.T) {
	snap := sampleLatestSnapshot()
	var out bytes.Buffer
	if err := report.FormatJSON(&out, snap); err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	var back report.Snapshot
	if err := json.Unmarshal(out.Bytes(), &back); err != nil {
		t.Fatalf("Unmarshal: %v (raw %q)", err, out.String())
	}
	if back.View != report.ViewLatest {
		t.Errorf("View = %q after round-trip", back.View)
	}
	if back.Latest == nil || len(back.Latest.Policies) != 2 {
		t.Errorf("policies survive: %#v", back.Latest)
	}
}

// TestFormatCSV_RowsHaveExpectedColumns confirms the header row + one
// data row per policy.
func TestFormatCSV_RowsHaveExpectedColumns(t *testing.T) {
	snap := sampleLatestSnapshot()
	var out bytes.Buffer
	if err := report.FormatCSV(&out, snap); err != nil {
		t.Fatalf("FormatCSV: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 { // header + 2 policies
		t.Errorf("line count = %d; want 3 (header + 2 policies). Got:\n%s", len(lines), out.String())
	}
	if !strings.HasPrefix(lines[0], "policy_id,control_id,status,severity") {
		t.Errorf("CSV header = %q", lines[0])
	}
}

// TestFormatText_ExceptionsAndIntegrity exercises the two non-latest
// formatters so we know they don't choke on representative data.
func TestFormatText_ExceptionsAndIntegrity(t *testing.T) {
	snapExc := &report.Snapshot{
		View: report.ViewExceptions, Framework: frameworkSOC2, PeriodID: testPeriodQ1,
		Exceptions: &report.ExceptionsView{Exceptions: []report.ExceptionEntry{
			{PolicyID: "p1", Scope: scopePolicy, State: statusWaived, ApprovedBy: "x@y", ApprovedAt: testApprovedAt, ExpiresAt: testExpiresAt, Reason: "ok"},
		}},
	}
	var b bytes.Buffer
	if err := report.FormatText(&b, snapExc); err != nil {
		t.Fatalf("text exceptions: %v", err)
	}
	if !strings.Contains(b.String(), "p1") || !strings.Contains(b.String(), statusWaived) {
		t.Errorf("exceptions text missing data: %q", b.String())
	}

	snapInt := &report.Snapshot{
		View: report.ViewIntegrity, Framework: frameworkSOC2, PeriodID: testPeriodQ1,
		Integrity: &report.IntegrityView{Runs: []report.IntegrityRow{
			{RunPath: "soc2/2026-Q1/run_x", RunID: "r1", SignatureValid: true, FilesVerified: 3, FilesTotal: 3},
		}},
	}
	b.Reset()
	if err := report.FormatText(&b, snapInt); err != nil {
		t.Fatalf("text integrity: %v", err)
	}
	if !strings.Contains(b.String(), statusPass) || !strings.Contains(b.String(), "3/3") {
		t.Errorf("integrity text missing data: %q", b.String())
	}
}

// TestFormatText_EmptyViews documents the "no data" branch each view
// renders so the formatters don't silently emit just a header.
func TestFormatText_EmptyViews(t *testing.T) {
	cases := []struct {
		name string
		snap *report.Snapshot
		want string
	}{
		{
			name: "latest",
			snap: &report.Snapshot{View: report.ViewLatest, Latest: &report.LatestView{}},
			want: "no policy results",
		},
		{
			name: "exceptions",
			snap: &report.Snapshot{View: report.ViewExceptions, Exceptions: &report.ExceptionsView{}},
			want: "no exceptions applied",
		},
		{
			name: "integrity",
			snap: &report.Snapshot{View: report.ViewIntegrity, Integrity: &report.IntegrityView{}},
			want: "no runs",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := report.FormatText(&b, c.snap); err != nil {
				t.Fatalf("FormatText: %v", err)
			}
			if !strings.Contains(b.String(), c.want) {
				t.Errorf("empty-view text missing %q: %q", c.want, b.String())
			}
		})
	}
}

// TestFormatters_RejectNilSnapshot covers the nil-Snapshot guard each
// formatter implements.
func TestFormatters_RejectNilSnapshot(t *testing.T) {
	var b bytes.Buffer
	if err := report.FormatText(&b, nil); err == nil {
		t.Error("FormatText(nil) = nil; want error")
	}
	if err := report.FormatJSON(&b, nil); err == nil {
		t.Error("FormatJSON(nil) = nil; want error")
	}
	if err := report.FormatCSV(&b, nil); err == nil {
		t.Error("FormatCSV(nil) = nil; want error")
	}
}

// TestFormatters_RejectUnsupportedView surfaces a clear error when the
// Snapshot.View doesn't match any of the three supported labels.
func TestFormatters_RejectUnsupportedView(t *testing.T) {
	bad := &report.Snapshot{View: "weird"}
	var b bytes.Buffer
	if err := report.FormatText(&b, bad); err == nil {
		t.Error("FormatText accepted unsupported view")
	}
	if err := report.FormatCSV(&b, bad); err == nil {
		t.Error("FormatCSV accepted unsupported view")
	}
}

// sampleLatestSnapshot returns a deterministic Snapshot used across
// the formatter tests.
func sampleLatestSnapshot() *report.Snapshot {
	when := time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC)
	return &report.Snapshot{
		View: report.ViewLatest, Framework: frameworkSOC2, PeriodID: testPeriodQ1,
		Latest: &report.LatestView{Policies: []report.LatestPolicy{
			{PolicyID: testPolicyMFA, ControlID: ctrlSOC2CC61, Status: statusPass, Severity: "high", Category: testCategoryAccess, LastEvaluated: when, RunID: "abcd1234"},
			{PolicyID: testPolicyAccessReview, ControlID: "SOC2.CC6.3", Status: statusFail, Severity: "medium", Category: testCategoryAccess, LastEvaluated: when, RunID: "abcd1234", ExceptionID: testPolicyAccessReview},
		}},
	}
}

// TestBuild_Integrity_HandlesMissingManifest documents that a run
// folder without a manifest.json shows up as an integrity failure
// (rather than crashing or being silently omitted).
func TestBuild_Integrity_HandlesMissingManifest(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Plant a stray file inside a run folder without ever writing a
	// manifest. The vault has no manifest to parse, so the row should
	// land in the integrity view as fail/missing-manifest.
	if err := v.PutBinary(context.Background(), "soc2/2026-Q1/run_20260215T140000Z_noooooo/summary.json", []byte(`{}`), nil); err != nil {
		t.Fatalf("plant file: %v", err)
	}
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewIntegrity,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(snap.Integrity.Runs) != 1 || snap.Integrity.Runs[0].Status() != statusFail {
		t.Errorf("expected one failing run; got %#v", snap.Integrity.Runs)
	}
}

// TestFormatCSV_Exceptions confirms the exceptions CSV emits the
// header + one row per exception with the configured columns.
func TestFormatCSV_Exceptions(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewExceptions, Framework: frameworkSOC2, PeriodID: testPeriodQ1,
		Exceptions: &report.ExceptionsView{Exceptions: []report.ExceptionEntry{
			{PolicyID: "p1", Scope: scopeLegacyIAMUser, State: statusWaived, ApprovedBy: "x@y", ApprovedAt: testApprovedAt, ExpiresAt: testExpiresAt, Reason: "needs rotation", FirstSeenRunID: "r1", LastSeenRunID: "r3"},
			{PolicyID: "p2", Scope: scopePolicy, State: "na", Reason: "out of scope"},
		}},
	}
	var b bytes.Buffer
	if err := report.FormatCSV(&b, snap); err != nil {
		t.Fatalf("FormatCSV: %v", err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Errorf("CSV lines = %d; want 3 (header + 2 rows): %q", len(lines), b.String())
	}
	if !strings.HasPrefix(lines[0], "policy_id,scope,state,approved_by") {
		t.Errorf("header = %q", lines[0])
	}
	if !strings.Contains(lines[1], statusWaived) || !strings.Contains(lines[1], "needs rotation") {
		t.Errorf("row 1 missing data: %q", lines[1])
	}
}

// TestFormatCSV_Integrity confirms the integrity CSV emits one row
// per run with a parseable status / files / mismatch path.
func TestFormatCSV_Integrity(t *testing.T) {
	snap := &report.Snapshot{
		View: report.ViewIntegrity, Framework: frameworkSOC2, PeriodID: testPeriodQ1,
		Integrity: &report.IntegrityView{Runs: []report.IntegrityRow{
			{RunPath: testRunPathA, RunID: "r1", SignatureValid: true, FilesVerified: 5, FilesTotal: 5},
			{RunPath: "soc2/2026-Q1/run_b", RunID: "r2", SignatureValid: true, FilesVerified: 2, FilesTotal: 3, FirstMismatchPath: summaryFileName, Error: "hash mismatch"},
		}},
	}
	var b bytes.Buffer
	if err := report.FormatCSV(&b, snap); err != nil {
		t.Fatalf("FormatCSV: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, statusPass) || !strings.Contains(out, statusFail) {
		t.Errorf("integrity CSV missing pass+fail rows: %q", out)
	}
	if !strings.Contains(out, summaryFileName) {
		t.Errorf("integrity CSV missing first_mismatch_path: %q", out)
	}
}

// TestFormatCSV_UnsupportedView surfaces a clear error when the
// snapshot's view is unknown, mirroring text's behavior.
func TestFormatCSV_UnsupportedView(t *testing.T) {
	var b bytes.Buffer
	if err := report.FormatCSV(&b, &report.Snapshot{View: "weird"}); err == nil {
		t.Error("FormatCSV accepted unsupported view")
	}
}

// TestBuild_Deterministic_LatestJSON_E2E is the end-to-end determinism
// check called out in the task spec: seed a vault with one+ runs,
// build the snapshot twice, format as JSON twice, and assert
// byte-identical output. Catches any nondeterministic map iteration
// or sort order that slipped into Build or the formatters.
func TestBuild_Deterministic_LatestJSON_E2E(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 5, 10, 0, 0, 0, time.UTC)
	seeds := []runSeed{
		{
			framework: frameworkSOC2, periodID: testPeriodQ1, runID: "runaaaaa", timestamp: t1, completedAt: t1,
			policies: []core.PolicyResult{
				{PolicyID: "p2", Controls: []core.ControlRef{{ControlID: "C2"}}, Status: core.StatusPass, Severity: core.SeverityMedium},
				{PolicyID: "p1", Controls: []core.ControlRef{{ControlID: "C1"}}, Status: core.StatusFail, Severity: core.SeverityHigh},
			},
		},
		{
			framework: frameworkSOC2, periodID: testPeriodQ1, runID: "runbbbbb", timestamp: t2, completedAt: t2,
			policies: []core.PolicyResult{
				{PolicyID: "p1", Controls: []core.ControlRef{{ControlID: "C1"}}, Status: core.StatusPass, Severity: core.SeverityHigh},
				{PolicyID: "p3", Controls: []core.ControlRef{{ControlID: "C3"}}, Status: core.StatusSkip, Severity: core.SeverityLow},
			},
		},
	}
	v, _ := makeVault(t, seeds)

	const runs = 3
	outs := make([]string, runs)
	for i := 0; i < runs; i++ {
		snap, err := report.Build(context.Background(), &report.Input{
			Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewLatest,
		})
		if err != nil {
			t.Fatalf("Build %d: %v", i, err)
		}
		var buf bytes.Buffer
		if err := report.FormatJSON(&buf, snap); err != nil {
			t.Fatalf("FormatJSON %d: %v", i, err)
		}
		outs[i] = buf.String()
	}
	for i := 1; i < runs; i++ {
		if outs[i] != outs[0] {
			t.Errorf("run %d differs from run 0:\nA:\n%s\nB:\n%s", i, outs[0], outs[i])
		}
	}
	// Spot-check: p1 should be pass (later run wins), p2 + p3 present.
	var snap report.Snapshot
	if err := json.Unmarshal([]byte(outs[0]), &snap); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := len(snap.Latest.Policies); got != 3 {
		t.Errorf("policies in latest = %d; want 3", got)
	}
}

// TestBuild_DefaultViewIsLatest documents that omitting --view (or
// passing the empty string) defaults to latest, matching the CLI.
func TestBuild_DefaultViewIsLatest(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v, _ := makeVault(t, []runSeed{
		{framework: frameworkSOC2, periodID: testPeriodQ1, runID: "default0", timestamp: t1, completedAt: t1,
			policies: []core.PolicyResult{{PolicyID: "p1", Status: core.StatusPass}}},
	})
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, // no View
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if snap.View != report.ViewLatest || snap.Latest == nil {
		t.Errorf("default view = %q; want latest", snap.View)
	}
}
