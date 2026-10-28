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

const (
	planted      = "policies/soc2.fake.policy/result.json"
	resultP1Path = "policies/p1/result.json"
)

// A file planted in a run folder after the manifest was signed is drift
// just as much as a modified one: the manifest vouches for a fixed set
// of files, and anything outside it is unverified.
func TestBuild_Integrity_FlagsFileNotInManifest(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v, roots := makeVault(t, []runSeed{{
		framework: frameworkSOC2, periodID: testPeriodQ1, runID: "planted0",
		timestamp: t1, completedAt: t1,
		policies: []core.PolicyResult{{PolicyID: "p1", Status: core.StatusPass}},
	}})
	if err := v.PutBinary(context.Background(), roots[0]+"/"+planted, []byte(`{"Status":"pass"}`), nil); err != nil {
		t.Fatal(err)
	}
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewIntegrity,
	})
	if err != nil {
		t.Fatal(err)
	}
	row := snap.Integrity.Runs[0]
	if row.Status() != statusFail {
		t.Fatalf("Status() = %q; want fail for a file the manifest does not list", row.Status())
	}
	if len(row.Problems) != 1 || row.Problems[0].Path != planted || row.Problems[0].Kind != report.ProblemNotInManifest {
		t.Errorf("Problems = %+v; want one not-in-manifest entry for %s", row.Problems, planted)
	}
	if row.FilesVerified != row.FilesTotal {
		t.Errorf("listed files should still verify: %d/%d", row.FilesVerified, row.FilesTotal)
	}
}

// Every bad file is reported, not just the first; later files are
// still verified so the count reflects what actually matched.
func TestBuild_Integrity_ReportsEveryProblem(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v, roots := makeVault(t, []runSeed{{
		framework: frameworkSOC2, periodID: testPeriodQ1, runID: "multibad",
		timestamp: t1, completedAt: t1,
		policies: []core.PolicyResult{
			{PolicyID: "p1", Status: core.StatusPass},
			{PolicyID: "p2", Status: core.StatusPass},
			{PolicyID: "p3", Status: core.StatusPass},
		},
		extraFiles: map[string][]byte{summaryFileName: []byte(`{"ok":true}`)},
	}})
	ctx := context.Background()
	if err := v.PutBinary(ctx, roots[0]+"/"+resultP1Path, []byte(`{}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := v.PutBinary(ctx, roots[0]+"/summary.json", []byte(`{"ok":false}`), nil); err != nil {
		t.Fatal(err)
	}
	snap, err := report.Build(ctx, &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewIntegrity,
	})
	if err != nil {
		t.Fatal(err)
	}
	row := snap.Integrity.Runs[0]
	if len(row.Problems) != 2 {
		t.Fatalf("Problems = %+v; want both tampered files", row.Problems)
	}
	if row.FilesVerified != row.FilesTotal-2 {
		t.Errorf("FilesVerified = %d of %d; want every untouched file verified", row.FilesVerified, row.FilesTotal)
	}
	if row.FirstMismatchPath != resultP1Path {
		t.Errorf("FirstMismatchPath = %q; want the first problem in path order", row.FirstMismatchPath)
	}
	var b bytes.Buffer
	if err := report.FormatText(&b, snap); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{resultP1Path, "summary.json"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("text output should name %s:\n%s", want, b.String())
		}
	}
	var c bytes.Buffer
	if err := report.FormatCSV(&c, snap); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.String(), "summary.json") || !strings.Contains(c.String(), resultP1Path) {
		t.Errorf("csv output should name both files:\n%s", c.String())
	}
}

// The latest view reads only results the manifest vouches for; a planted
// result.json must not show up as a policy outcome.
func TestBuild_Latest_IgnoresFilesNotInManifest(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v, roots := makeVault(t, []runSeed{{
		framework: frameworkSOC2, periodID: testPeriodQ1, runID: "planted1",
		timestamp: t1, completedAt: t1,
		policies: []core.PolicyResult{{PolicyID: "p1", Status: core.StatusPass}},
	}})
	if err := v.PutBinary(context.Background(), roots[0]+"/"+planted, []byte(`{"Status":"pass"}`), nil); err != nil {
		t.Fatal(err)
	}
	snap, err := report.Build(context.Background(), &report.Input{
		Vault: v, Framework: frameworkSOC2, PeriodID: testPeriodQ1, View: report.ViewLatest,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range snap.Latest.Policies {
		if p.PolicyID == "soc2.fake.policy" {
			t.Errorf("latest view shows a result the manifest does not list: %+v", p)
		}
	}
}

func TestBuild_RunCountAndListPeriods(t *testing.T) {
	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	v, _ := makeVault(t, []runSeed{
		{framework: frameworkSOC2, periodID: testPeriodQ1, runID: "count001", timestamp: t1, completedAt: t1},
		{framework: frameworkSOC2, periodID: testPeriodQ2, runID: "count002", timestamp: t2, completedAt: t2},
	})
	ctx := context.Background()
	snap, err := report.Build(ctx, &report.Input{Vault: v, Framework: frameworkSOC2, PeriodID: "2026-Q4", View: report.ViewIntegrity})
	if err != nil {
		t.Fatal(err)
	}
	if snap.RunCount != 0 {
		t.Errorf("RunCount = %d; want 0 for an empty period", snap.RunCount)
	}
	periods, err := report.ListPeriods(ctx, v, frameworkSOC2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(periods, ",") != testPeriodQ1+","+testPeriodQ2 {
		t.Errorf("ListPeriods = %v", periods)
	}
}
