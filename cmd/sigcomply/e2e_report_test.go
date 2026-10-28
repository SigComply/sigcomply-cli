package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/report"
)

// runReportJSON runs `report --view <view> --format json` against the
// project and decodes the snapshot. want is the exit code.
func runReportJSON(t *testing.T, p e2eProject, view string, want int) (report.Snapshot, e2eResult) {
	t.Helper()
	out := filepath.Join(p.dir, "report-"+view+".json")
	res := runSigcomply(t, p.dir, nil, "report", "--period", e2ePeriod, "--view", view, "--format", "json", "--out", out)
	res.wantCode(t, want)
	var snap report.Snapshot
	readJSON(t, out, &snap)
	if string(snap.View) != view || snap.PeriodID != e2ePeriod {
		t.Errorf("report --view %s: snapshot view=%q period=%q", view, snap.View, snap.PeriodID)
	}
	return snap, res
}

// TestBinaryE2E_Report_ReadsTheVaultCheckWrote runs `report` on the vault
// a real `check` wrote, not a hand-built fixture, so a change to what
// check writes that report can no longer read fails here.
func TestBinaryE2E_Report_ReadsTheVaultCheckWrote(t *testing.T) {
	p := newE2EProject(t)
	// One missing document, so the run holds a fail beside the passes.
	// Its control (C1.2) rests on documents alone, so coverage must
	// count it missing.
	const removed = "data_retention_policy"
	var found bool
	for _, f := range seedAllManualEvidence(t, p) {
		if strings.Contains(filepath.ToSlash(f), "/manual/"+removed+"/") {
			if err := os.Remove(f); err != nil {
				t.Fatal(err)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no seeded folder for %s", removed)
	}
	runSigcomply(t, p.dir, nil, "check", "--no-cloud").wantCode(t, 1)
	runDir := singleRunDir(t, p.vault, defaultFW)
	results := readResultStatuses(t, runDir)

	t.Run("latest matches result.json", func(t *testing.T) {
		checkLatestView(t, p, results, removed)
	})
	t.Run("coverage", func(t *testing.T) {
		snap, _ := runReportJSON(t, p, viewCoverage, 0)
		cov := snap.Coverage
		if cov == nil {
			t.Fatal("no coverage view in the snapshot")
		}
		if cov.ManualMissing != 1 || cov.ManualOnFile == 0 {
			t.Errorf("coverage: manual on file %d, missing %d; want one control missing its document", cov.ManualOnFile, cov.ManualMissing)
		}
		statuses := map[string]string{}
		for i := range cov.Rows {
			statuses[cov.Rows[i].ControlID] = cov.Rows[i].Assurance + "/" + cov.Rows[i].Status
		}
		assertE2EGolden(t, "soc2_coverage_one_missing", statuses)
	})
	t.Run("soa", func(t *testing.T) {
		snap, _ := runReportJSON(t, p, viewSoA, 0)
		if snap.SoA == nil || len(snap.SoA.Rows) == 0 {
			t.Fatal("no SoA rows")
		}
		assertSoASums(t, snap.SoA)
	})
	t.Run("integrity passes, then fails on a tampered file", func(t *testing.T) {
		checkIntegrityAndTamper(t, p, runDir)
	})
}

func checkLatestView(t *testing.T, p e2eProject, results map[string]core.PolicyStatus, removed string) {
	t.Helper()
	snap, _ := runReportJSON(t, p, viewLatest, 0)
	if snap.Latest == nil {
		t.Fatal("no latest view in the snapshot")
	}
	got := map[string]core.PolicyStatus{}
	for i := range snap.Latest.Policies {
		got[snap.Latest.Policies[i].PolicyID] = core.PolicyStatus(snap.Latest.Policies[i].Status)
	}
	if len(got) != len(results) {
		t.Errorf("latest view has %d policies; the run wrote %d results", len(got), len(results))
	}
	failed := 0
	for id, want := range results {
		if got[id] != want {
			t.Errorf("%s: latest view says %q; result.json says %q", id, got[id], want)
		}
		if want == core.StatusFail {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("run has %d failing policies; want exactly the one with its document removed (%s)", failed, removed)
	}
}

func checkIntegrityAndTamper(t *testing.T, p e2eProject, runDir string) {
	t.Helper()
	snap, _ := runReportJSON(t, p, viewIntegrity, 0)
	var manifest core.Manifest
	readJSON(t, filepath.Join(runDir, "manifest.json"), &manifest)
	if snap.Integrity == nil || len(snap.Integrity.Runs) != 1 {
		t.Fatalf("integrity view: want one run, got %+v", snap.Integrity)
	}
	row := snap.Integrity.Runs[0]
	if !row.SignatureValid || row.FilesVerified != len(manifest.FileHashes) || row.FilesTotal != len(manifest.FileHashes) {
		t.Errorf("integrity row = %+v; want a valid signature and all %d files verified", row, len(manifest.FileHashes))
	}

	// Flip one result's status on disk: the manifest hash no longer
	// matches, and the view must say which file and exit 1.
	const tampered = "policies/soc2.cc6.3.access_review_quarterly/result.json"
	path := filepath.Join(runDir, filepath.FromSlash(tampered))
	body, err := os.ReadFile(path) //nolint:gosec // #nosec G304 -- the test's own vault
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(body), `"pass"`, `"fail"`, 1)
	if edited == string(body) {
		t.Fatalf("%s holds no pass status to tamper with", tampered)
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil { //nolint:gosec // #nosec G703 -- a fixed path inside the test's own vault
		t.Fatal(err)
	}
	snap, res := runReportJSON(t, p, viewIntegrity, 1)
	row = snap.Integrity.Runs[0]
	if row.FirstMismatchPath != tampered || row.Status() != "fail" {
		t.Errorf("tampered run: status %s, first mismatch %q; want fail at %s", row.Status(), row.FirstMismatchPath, tampered)
	}
	if !strings.Contains(res.stderr, "integrity verification failed for 1 of 1 run(s)") {
		t.Errorf("stderr does not report the failed run:\n%s", res.stderr)
	}
}

// assertSoASums checks the SoA's headline counts add up to its rows.
func assertSoASums(t *testing.T, soa *report.SoAView) {
	t.Helper()
	if soa.Controls != len(soa.Rows) {
		t.Errorf("SoA headline says %d controls, table has %d rows", soa.Controls, len(soa.Rows))
	}
	if soa.Applicable+soa.Excluded != soa.Controls {
		t.Errorf("SoA: applicable %d + excluded %d != %d controls", soa.Applicable, soa.Excluded, soa.Controls)
	}
	if soa.Implemented+soa.Partial+soa.NotImplemented+soa.NotEvaluated != soa.Applicable {
		t.Errorf("SoA: implemented %d + partial %d + not implemented %d + not evaluated %d != %d applicable",
			soa.Implemented, soa.Partial, soa.NotImplemented, soa.NotEvaluated, soa.Applicable)
	}
}

// TestBinaryE2E_Check_ISO27001 runs the second shipped framework through
// the binary: unseeded it fails, seeded it passes, and the Statement of
// Applicability (the ISO deliverable) reads the vault the run wrote.
func TestBinaryE2E_Check_ISO27001(t *testing.T) {
	unseeded := newE2EProjectFor(t, isoFW, "")
	res := runSigcomply(t, unseeded.dir, nil, "check", "--no-cloud")
	res.wantCode(t, 1)
	if !strings.Contains(res.stdout, "SigComply check "+isoFW+"/"+e2ePeriod) {
		t.Errorf("stdout missing run header for %s/%s:\n%s", isoFW, e2ePeriod, res.stdout)
	}
	assertVaultSigned(t, singleRunDir(t, unseeded.vault, isoFW))

	p := newE2EProjectFor(t, isoFW, "")
	seedAllManualEvidence(t, p)
	runSigcomply(t, p.dir, nil, "check", "--no-cloud").wantCode(t, 0)
	runDir := singleRunDir(t, p.vault, isoFW)
	assertOutcomesGolden(t, runDir, "iso27001_manual_seeded")
	assertVaultSigned(t, runDir)

	snap, _ := runReportJSON(t, p, viewSoA, 0)
	if snap.SoA == nil || len(snap.SoA.Rows) == 0 {
		t.Fatal("no SoA rows")
	}
	assertSoASums(t, snap.SoA)
	statuses := map[string]string{}
	for i := range snap.SoA.Rows {
		statuses[snap.SoA.Rows[i].ControlID] = snap.SoA.Rows[i].Status
	}
	assertE2EGolden(t, "iso27001_soa_seeded", statuses)
}
