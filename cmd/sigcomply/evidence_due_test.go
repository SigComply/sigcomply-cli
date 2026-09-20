package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/manualdue"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
)

// writeDueProject lays down a minimal project whose manual evidence
// lives on the local backend, so the due scan exercises a real Reader
// rather than a stub.
func writeDueProject(t *testing.T) (dir, configPath string) {
	t.Helper()
	dir = t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.MkdirAll(store, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	cfg := "schema_version: project.v1\nframework: soc2\n" +
		"vault:\n  backend: local\n  path: " + filepath.Join(dir, "vault") + "\n" +
		"sources:\n  manual.pdf:\n    backend: local\n    path: " + store + "\n    prefix: manual/\n"
	configPath = filepath.Join(dir, ".sigcomply.yaml")
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir, configPath
}

func runDue(t *testing.T, configPath string, parent *evidenceFlags, flags *evidenceDueFlags) (string, error) {
	t.Helper()
	flags.config = configPath
	var out bytes.Buffer
	err := runEvidenceDue(context.Background(), &out, parent, flags)
	return out.String(), err
}

func TestEvidenceDue_ReportsEmptyFolders(t *testing.T) {
	_, cfg := writeDueProject(t)
	out, err := runDue(t, cfg, &evidenceFlags{output: outputText}, &evidenceDueFlags{all: true})
	if err != nil {
		t.Fatalf("runEvidenceDue: %v", err)
	}
	if !strings.Contains(out, "have an empty folder") {
		t.Errorf("expected a due block, got:\n%s", out)
	}
	// Every SOC 2 entry but three is annual, and an annual entry's
	// folder is the year — not the quarter the run lands in.
	if !regexp.MustCompile(`security_awareness_training/\d{4}/`).MatchString(out) {
		t.Errorf("annual entry not reported under its year folder, got:\n%s", out)
	}
}

func TestEvidenceDue_ExitsZeroWhenEvidenceIsDue(t *testing.T) {
	_, cfg := writeDueProject(t)
	_, err := runDue(t, cfg, &evidenceFlags{output: outputText}, &evidenceDueFlags{all: true})
	if err != nil {
		t.Fatalf("due evidence must not produce an error; got %v", err)
	}
}

// A populated folder drops out of the report entirely. This is the
// property that keeps the notice credible enough to act on.
func TestEvidenceDue_PopulatedFolderIsOmitted(t *testing.T) {
	dir, cfg := writeDueProject(t)

	var before manualdue.Report
	out, err := runDue(t, cfg, &evidenceFlags{output: outputJSON}, &evidenceDueFlags{all: true})
	if err != nil {
		t.Fatalf("runEvidenceDue: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &before); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(before.Missing) == 0 {
		t.Fatal("expected missing entries on an empty store")
	}

	target := before.Missing[0]
	folder := filepath.Join(dir, "store", "manual", target.CatalogID, target.PeriodID)
	if err := os.MkdirAll(folder, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(folder, "evidence.pdf"), []byte("%PDF-1.4\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var after manualdue.Report
	out, err = runDue(t, cfg, &evidenceFlags{output: outputJSON}, &evidenceDueFlags{all: true})
	if err != nil {
		t.Fatalf("runEvidenceDue: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &after); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(after.Missing) != len(before.Missing)-1 {
		t.Errorf("Missing = %d; want %d", len(after.Missing), len(before.Missing)-1)
	}
	for _, e := range after.Missing {
		if e.CatalogID == target.CatalogID {
			t.Errorf("%s still reported after its folder was populated", target.CatalogID)
		}
	}
}

// An automated-only project is a legitimate configuration, not an error.
func TestEvidenceDue_NoManualSourceIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	cfg := "schema_version: project.v1\nframework: soc2\n" +
		"vault:\n  backend: local\n  path: " + filepath.Join(dir, "vault") + "\n" +
		"sources:\n  aws.iam:\n    region: us-east-1\n"
	configPath := filepath.Join(dir, ".sigcomply.yaml")
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	out, err := runDue(t, configPath, &evidenceFlags{output: outputText}, &evidenceDueFlags{})
	if err != nil {
		t.Fatalf("expected no error; got %v", err)
	}
	if !strings.Contains(out, "no manual.pdf source configured") {
		t.Errorf("expected an explanatory note, got:\n%s", out)
	}
}

func TestEvidenceDue_MissingConfigExits3(t *testing.T) {
	_, err := runDue(t, filepath.Join(t.TempDir(), "nope.yaml"),
		&evidenceFlags{output: outputText}, &evidenceDueFlags{})
	assertExitCode(t, err, orchestrator.ExitConfig)
}

func TestEvidenceDue_UnknownFrameworkExits3(t *testing.T) {
	_, cfg := writeDueProject(t)
	_, err := runDue(t, cfg, &evidenceFlags{framework: "nope", output: outputText}, &evidenceDueFlags{})
	assertExitCode(t, err, orchestrator.ExitConfig)
}

func TestEvidenceDue_BadOutputFormatExits3(t *testing.T) {
	_, cfg := writeDueProject(t)
	_, err := runDue(t, cfg, &evidenceFlags{output: formatYAML}, &evidenceDueFlags{})
	assertExitCode(t, err, orchestrator.ExitConfig)
}

func assertExitCode(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error with exit code %d", want)
	}
	var ec *exitCodeError
	if !errors.As(err, &ec) {
		t.Fatalf("error is not an exitCodeError: %v", err)
	}
	if ec.code != want {
		t.Errorf("exit code = %d; want %d", ec.code, want)
	}
}
