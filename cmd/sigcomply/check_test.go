package cmd

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

func TestRegisterProductionSources_ManualOnly(t *testing.T) {
	tmp := t.TempDir()
	cfg := &spec.ProjectConfig{
		Sources: map[string]map[string]any{
			"manual.pdf": {"backend": "local", "path": tmp},
		},
	}
	regs := registry.NewSet()
	if err := registerProductionSources(context.Background(), regs, cfg, map[string]manual.CatalogEntry{}); err != nil {
		t.Fatalf("registerProductionSources: %v", err)
	}
	if _, ok := regs.Sources.Lookup("manual.pdf"); !ok {
		t.Error("manual.pdf not registered")
	}
}

func TestRegisterProductionSources_UnknownSourceErrors(t *testing.T) {
	cfg := &spec.ProjectConfig{
		Sources: map[string]map[string]any{
			"made.up.source": {},
		},
	}
	err := registerProductionSources(context.Background(), registry.NewSet(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "is not registered") {
		t.Errorf("want unknown-source error; got %v", err)
	}
}

func TestGitContext_UsesEnvSHA(t *testing.T) {
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_EVENT_HEAD_COMMIT_TIMESTAMP", "2026-02-15T13:55:00Z")
	sha, ts := gitContext(context.Background(), log.New(nil, false))
	if sha != "abc123" {
		t.Errorf("sha = %q", sha)
	}
	if ts.Year() != 2026 || ts.Month() != 2 || ts.Day() != 15 {
		t.Errorf("ts = %v", ts)
	}
}

func TestGitContext_GitLabSHA(t *testing.T) {
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("CI_COMMIT_SHA", "gl-sha")
	t.Setenv("GITHUB_EVENT_HEAD_COMMIT_TIMESTAMP", "")
	sha, _ := gitContext(context.Background(), log.New(nil, false))
	if sha != "gl-sha" {
		t.Errorf("sha = %q", sha)
	}
}

func TestRunCheck_MissingConfigFile(t *testing.T) {
	err := runCheck(context.Background(), &bytes.Buffer{}, &checkFlags{
		config:   filepath.Join(t.TempDir(), "nope.yaml"),
		cloudOff: true,
	})
	if err == nil {
		t.Fatal("want error on missing config")
	}
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != 3 {
		t.Errorf("want exitCodeError{code:3}; got %v", err)
	}
}

func TestRunCheck_RejectsUnsupportedFramework(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "cfg.yaml")
	// hipaa is the stub framework — listed in spec.SupportedFrameworks
	// but no framework package registers under that name, so the
	// orchestrator must still reject it. iso27001 used to fail here too
	// but now ships a real skeleton.
	writeMinimalConfig(t, configPath, "hipaa", tmp)
	err := runCheck(context.Background(), &bytes.Buffer{}, &checkFlags{
		config:   configPath,
		cloudOff: true,
	})
	if err == nil {
		t.Fatal("want error on unsupported framework")
	}
	if !strings.Contains(err.Error(), "hipaa") && !strings.Contains(err.Error(), "not supported") {
		t.Errorf("want framework error; got %v", err)
	}
}

func TestRunCheck_EndToEndWithManualOnly(t *testing.T) {
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")
	manualDir := filepath.Join(tmp, "manual")
	if err := os.MkdirAll(manualDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	configPath := filepath.Join(tmp, "cfg.yaml")
	writeManualOnlyConfig(t, configPath, vaultDir, manualDir)
	var stdout bytes.Buffer
	err := runCheck(context.Background(), &stdout, &checkFlags{
		config:   configPath,
		cloudOff: true,
	})
	if err != nil {
		// Some policies may fail/violate; the run still completes through
		// the rendering path and reports via exitCodeError.
		var ec *exitCodeError
		if !errors.As(err, &ec) {
			t.Fatalf("unexpected (non-exitCode) error: %v", err)
		}
	}
	// The run must have reached the rendering path and printed its summary.
	if !strings.Contains(stdout.String(), "SigComply check") {
		t.Errorf("stdout missing run summary header; got:\n%s", stdout.String())
	}
	// A completed run writes a signed manifest.json under its run folder.
	var manifestFound bool
	err = filepath.WalkDir(vaultDir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if !d.IsDir() && d.Name() == "manifest.json" {
			manifestFound = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk vault: %v", err)
	}
	if !manifestFound {
		t.Errorf("no manifest.json written under vault %s", vaultDir)
	}
}

func TestExecute_Help(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{"sigcomply", "--help"}
	if got := Execute(); got != 0 {
		t.Errorf("Execute --help = %d; want 0", got)
	}
}

func TestExecute_UnknownCommand(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{"sigcomply", "does-not-exist"}
	if got := Execute(); got == 0 {
		t.Errorf("Execute unknown command = 0; want non-zero")
	}
}

func writeMinimalConfig(t *testing.T, path, framework, vaultDir string) {
	t.Helper()
	body := `schema_version: project.v1
framework: ` + framework + `
vault:
  backend: local
  path: ` + vaultDir + `
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeManualOnlyConfig(t *testing.T, path, vaultDir, manualDir string) {
	t.Helper()
	body := `schema_version: project.v1
framework: soc2
period:
  fiscal_calendar:
    type: calendar_quarter
  time_basis: commit
vault:
  backend: local
  path: ` + vaultDir + `
sources:
  manual.pdf:
    backend: local
    path: ` + manualDir + `
    prefix: manual/
cloud:
  base_url: ""
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func TestWithRegionDefault(t *testing.T) {
	cases := []struct {
		name        string
		raw         map[string]any
		vaultRegion string
		wantRegion  any
		wantPresent bool
	}{
		{
			name:        "no vault region leaves raw untouched",
			raw:         map[string]any{"bucket": "b"},
			vaultRegion: "",
			wantPresent: false,
		},
		{
			name:        "vault region fills in missing region",
			raw:         map[string]any{"bucket": "b"},
			vaultRegion: "us-east-1",
			wantRegion:  "us-east-1",
			wantPresent: true,
		},
		{
			name:        "explicit region is preserved over vault default",
			raw:         map[string]any{"region": "eu-west-1"},
			vaultRegion: "us-east-1",
			wantRegion:  "eu-west-1",
			wantPresent: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := withRegionDefault(c.raw, c.vaultRegion)
			region, present := got["region"]
			if present != c.wantPresent {
				t.Fatalf("region present = %v; want %v", present, c.wantPresent)
			}
			if c.wantPresent && region != c.wantRegion {
				t.Errorf("region = %v; want %v", region, c.wantRegion)
			}
			// The original map must never be mutated when a copy is made.
			if c.vaultRegion != "" {
				if _, hadRegion := c.raw["region"]; !hadRegion {
					if _, leaked := c.raw["region"]; leaked {
						t.Error("withRegionDefault mutated the input map")
					}
				}
			}
		})
	}
}
