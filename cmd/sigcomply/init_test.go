package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// isoFW is the ISO 27001 identifier — bound here so the goconst linter
// doesn't trip on the repeated literal across the cmd test files.
const isoFW = "iso27001"

// TestInit_ScaffoldsValidConfig is the load-bearing guarantee: whatever
// `sigcomply init` writes must parse and validate through the real spec
// loader, so a brand-new user's first `sigcomply check` doesn't trip on a
// malformed scaffold.
func TestInit_ScaffoldsValidConfig(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, ".sigcomply.yaml")

	var buf bytes.Buffer
	if err := runInit(&buf, initFlags{framework: defaultFW, out: out}); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read scaffold: %v", err)
	}
	cfg, err := spec.LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("scaffolded config does not validate: %v", err)
	}
	if cfg.Framework != defaultFW {
		t.Errorf("Framework = %q; want %s", cfg.Framework, defaultFW)
	}
	// Vault defaults must be present (the active block sets local).
	if cfg.Vault.Backend != "local" {
		t.Errorf("Vault.Backend = %q; want local", cfg.Vault.Backend)
	}
	// aws.iam is the active example source.
	if _, ok := cfg.Sources["aws.iam"]; !ok {
		t.Errorf("expected aws.iam in scaffolded sources, got %v", cfg.Sources)
	}
	// No policies: block — auto-binding carries the first run.
	if len(cfg.Policies) != 0 {
		t.Errorf("expected no policies: block in scaffold, got %v", cfg.Policies)
	}
	if !strings.Contains(buf.String(), "Next steps") {
		t.Errorf("expected next-steps guidance in output, got %q", buf.String())
	}
}

func TestInit_Iso27001(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "cfg.yaml")
	if err := runInit(&bytes.Buffer{}, initFlags{framework: isoFW, out: out}); err != nil {
		t.Fatalf("runInit(iso27001): %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read scaffold: %v", err)
	}
	cfg, err := spec.LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("iso27001 scaffold does not validate: %v", err)
	}
	if cfg.Framework != isoFW {
		t.Errorf("Framework = %q; want %s", cfg.Framework, isoFW)
	}
}

func TestInit_RejectsUnknownFramework(t *testing.T) {
	out := filepath.Join(t.TempDir(), ".sigcomply.yaml")
	err := runInit(&bytes.Buffer{}, initFlags{framework: "hipaa", out: out})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("want not-supported error for hipaa; got %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("no file should be written for an unsupported framework")
	}
}

func TestInit_RefusesOverwriteWithoutForce(t *testing.T) {
	out := filepath.Join(t.TempDir(), ".sigcomply.yaml")
	if err := os.WriteFile(out, []byte("existing: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runInit(&bytes.Buffer{}, initFlags{framework: defaultFW, out: out})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("want refuse-overwrite error; got %v", err)
	}
	// Original content untouched.
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read existing: %v", err)
	}
	if !strings.Contains(string(data), "existing: true") {
		t.Errorf("existing file was modified despite no --force")
	}
	// With --force it overwrites.
	if err := runInit(&bytes.Buffer{}, initFlags{framework: defaultFW, out: out, force: true}); err != nil {
		t.Fatalf("runInit --force: %v", err)
	}
	data, err = os.ReadFile(out)
	if err != nil {
		t.Fatalf("read after force: %v", err)
	}
	if strings.Contains(string(data), "existing: true") {
		t.Errorf("--force did not overwrite the file")
	}
}

func TestResolveInitFramework(t *testing.T) {
	t.Setenv("SIGCOMPLY_FRAMEWORK", "")
	if got := resolveInitFramework(""); got != defaultFW {
		t.Errorf("default = %q; want %s", got, defaultFW)
	}
	if got := resolveInitFramework(isoFW); got != isoFW {
		t.Errorf("flag wins = %q; want %s", got, isoFW)
	}
	t.Setenv("SIGCOMPLY_FRAMEWORK", isoFW)
	if got := resolveInitFramework(""); got != isoFW {
		t.Errorf("env = %q; want %s", got, isoFW)
	}
}
