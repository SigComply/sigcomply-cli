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
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

func TestRegisterProductionSources_ManualOnly(t *testing.T) {
	tmp := t.TempDir()
	cfg := &spec.ProjectConfig{
		Sources: map[string]map[string]any{
			"manual.pdf": {"backend": backendLocal, "path": tmp},
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
	// No evidence is uploaded, so the manual policies fail: a completed
	// run with violations, exit 1, and no error message.
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != orchestrator.ExitViolation || ec.err != nil {
		t.Fatalf("want bare exitCodeError{code:%d}; got %v", orchestrator.ExitViolation, err)
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
	// The run ends by naming where its results went and how to read
	// them back; nothing else in the output names the vault.
	if !strings.Contains(stdout.String(), "Results written to "+vaultDir+"/soc2/") ||
		!strings.Contains(stdout.String(), "Next: sigcomply report --period ") {
		t.Errorf("stdout should name the run folder and the report command; got:\n%s", stdout.String())
	}
}

func TestExecute_Help(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{testBinaryName, "--help"}
	if got := Execute(); got != 0 {
		t.Errorf("Execute --help = %d; want 0", got)
	}
}

func TestExecute_UnknownCommand(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{testBinaryName, "does-not-exist"}
	// An unknown command is a usage error: exit 2, not the config code 3
	// and not 1, which CI reads as a policy violation.
	if got := Execute(); got != orchestrator.ExitExecution {
		t.Errorf("Execute unknown command = %d; want %d", got, orchestrator.ExitExecution)
	}
}

// A config mistake the planner catches (here: a roster source that is not
// configured) is a configuration error, so the binary must exit 3 — the
// code orchestrator.Run reports — not the generic execution code 2.
func TestRunCheck_PlanErrorExitsConfig(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "cfg.yaml")
	manualDir := filepath.Join(tmp, "manual")
	if err := os.MkdirAll(manualDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeManualOnlyConfig(t, configPath, filepath.Join(tmp, "vault"), manualDir)
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("experimental:\n  roster:\n    source: okta\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	err = runCheck(context.Background(), &bytes.Buffer{}, &checkFlags{config: configPath, cloudOff: true})
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != orchestrator.ExitConfig {
		t.Fatalf("want exitCodeError{code:3}; got %v", err)
	}
	if !strings.Contains(err.Error(), "experimental.roster.source") {
		t.Errorf("want the roster error surfaced; got %v", err)
	}
}

// cadenceAnnualName is the annual cadence value as a user types it.
const cadenceAnnualName = "annual"

// A mistyped cadence used to select 0 policies and exit 0, so a CI job
// with a typo stayed green while checking nothing.
func TestRunCheck_UnknownCadenceExitsConfig(t *testing.T) {
	cases := []struct {
		name  string
		flags checkFlags
		bad   string
	}{
		{"cadence", checkFlags{cadence: "yearly"}, "yearly"},
		{"cadences", checkFlags{cadences: []string{"daily", "bogus"}}, "bogus"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			configPath := filepath.Join(tmp, "cfg.yaml")
			manualDir := filepath.Join(tmp, "manual")
			if err := os.MkdirAll(manualDir, 0o750); err != nil {
				t.Fatal(err)
			}
			writeManualOnlyConfig(t, configPath, filepath.Join(tmp, "vault"), manualDir)
			flags := c.flags
			flags.config = configPath
			flags.cloudOff = true
			err := runCheck(context.Background(), &bytes.Buffer{}, &flags)
			var ec *exitCodeError
			if !errors.As(err, &ec) || ec.code != orchestrator.ExitConfig {
				t.Fatalf("want exitCodeError{code:3}; got %v", err)
			}
			for _, want := range []string{c.bad, cadenceAnnualName} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v; want it to name %q", err, want)
				}
			}
		})
	}
}

// Config mistakes the loader catches stop the run before any source is
// built, with exit 3 and a message naming the key.
func TestRunCheck_LoadTimeConfigErrorsExitConfig(t *testing.T) {
	cases := []struct {
		name, appended, want string
	}{
		{"removed key", "ci:\n  fail_severity: high\n", `"ci.fail_severity" was removed and has no effect`},
		{"malformed scope", "experimental:\n  scope:\n    required_sources: github\n", "experimental.scope.required_sources"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			configPath := filepath.Join(tmp, "cfg.yaml")
			manualDir := filepath.Join(tmp, "manual")
			if err := os.MkdirAll(manualDir, 0o750); err != nil {
				t.Fatal(err)
			}
			writeManualOnlyConfig(t, configPath, filepath.Join(tmp, "vault"), manualDir)
			f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(c.appended); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			err = runCheck(context.Background(), &bytes.Buffer{}, &checkFlags{config: configPath, cloudOff: true})
			var ec *exitCodeError
			if !errors.As(err, &ec) || ec.code != orchestrator.ExitConfig {
				t.Fatalf("want exitCodeError{code:3}; got %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v; want it to contain %q", err, c.want)
			}
		})
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
			vaultRegion: testAWSRegion,
			wantRegion:  testAWSRegion,
			wantPresent: true,
		},
		{
			name:        "explicit region is preserved over vault default",
			raw:         map[string]any{"region": "eu-west-1"},
			vaultRegion: testAWSRegion,
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

func TestCILocalStorageWarnings(t *testing.T) {
	cfg := &spec.ProjectConfig{
		Vault:   spec.VaultConfig{Backend: backendLocal, Config: map[string]any{pathKey: "./.sigcomply/vault"}},
		Sources: map[string]map[string]any{manual.SourceID: {pathKey: "./evidence"}},
	}
	if w := ciLocalStorageWarnings(cfg, false); len(w) != 0 {
		t.Errorf("no warnings outside CI; got %v", w)
	}
	w := ciLocalStorageWarnings(cfg, true)
	if len(w) != 2 || !strings.Contains(w[0], "vault") || !strings.Contains(w[1], manual.SourceID) {
		t.Errorf("want vault and manual.pdf warnings in CI; got %v", w)
	}
	cfg.Vault = spec.VaultConfig{Backend: s3Backend, Config: map[string]any{bucketKey: "b"}}
	cfg.Sources[manual.SourceID]["backend"] = s3Backend
	if w := ciLocalStorageWarnings(cfg, true); len(w) != 0 {
		t.Errorf("bucket storage must not warn; got %v", w)
	}
}

func TestVaultLocation(t *testing.T) {
	cases := map[string]spec.VaultConfig{
		"./v":           {Backend: backendLocal, Config: map[string]any{pathKey: "./v/"}},
		"s3://b/p":      {Backend: s3Backend, Config: map[string]any{bucketKey: "b", prefixConfigKey: "p/"}},
		"gs://b":        {Backend: "gcs", Config: map[string]any{bucketKey: "b"}},
		"az://acct/box": {Backend: azureBlobBackend, Config: map[string]any{accountKey: "acct", containerKey: "box"}},
	}
	for want, vc := range cases {
		if got := vaultLocation(&vc); got != want {
			t.Errorf("vaultLocation(%+v) = %q; want %q", vc, got, want)
		}
	}
}

// A plain-http cloud URL would send the OIDC token in cleartext; it is a
// config error before the run, whether it comes from the config or the
// flag.
func TestRunCheck_PlainHTTPCloudURLExitsConfig(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "cfg.yaml")
	writeManualOnlyConfig(t, configPath, filepath.Join(tmp, "vault"), filepath.Join(tmp, "manual"))
	err := runCheck(context.Background(), &bytes.Buffer{}, &checkFlags{
		config: configPath, cloudURL: "http://sigcomply.example",
	})
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != orchestrator.ExitConfig || !strings.Contains(err.Error(), "https") {
		t.Fatalf("want exit 3 naming https; got %v", err)
	}
}

// --capture-cloud-payload names a file the operator asked for; failing to
// write it exits 2 rather than 0 or the policy verdict.
func TestRunCheck_CaptureWriteFailureExitsTwo(t *testing.T) {
	tmp := t.TempDir()
	manualDir := filepath.Join(tmp, "manual")
	if err := os.MkdirAll(manualDir, 0o750); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(tmp, "cfg.yaml")
	writeManualOnlyConfig(t, configPath, filepath.Join(tmp, "vault"), manualDir)
	err := runCheck(context.Background(), &bytes.Buffer{}, &checkFlags{
		config: configPath, capturePayloadPath: filepath.Join(tmp, "missing-dir", "payload.json"),
	})
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != orchestrator.ExitExecution || !strings.Contains(err.Error(), "payload.json") {
		t.Fatalf("want exit 2 naming the capture file; got %v", err)
	}
}

// A run that would submit (unfiltered or --scheduled, a cloud URL
// resolved, no --no-cloud) but names no project warns before collection.
// A filtered run never submits, so it stays quiet. Release N only warns;
// the next release makes it a config error.
func TestMissingProjectIDWarning(t *testing.T) {
	const url = "https://sigcomply.com"
	withID := &spec.ProjectConfig{Cloud: spec.CloudConfig{BaseURL: url, ProjectID: "prj_7Xq2mKp9RtV4wNc8Bz3a"}}
	noID := &spec.ProjectConfig{Cloud: spec.CloudConfig{BaseURL: url}}
	cases := []struct {
		name      string
		cfg       *spec.ProjectConfig
		cloudBase string
		flags     checkFlags
		want      bool
	}{
		{"cloud url without project id", noID, url, checkFlags{}, true},
		{"--scheduled without project id", noID, url, checkFlags{scheduled: true}, true},
		{"--cloud-url without project id", &spec.ProjectConfig{}, url, checkFlags{cloudURL: url}, true},
		{"cloud url with project id", withID, url, checkFlags{}, false},
		{"--no-cloud", noID, url, checkFlags{cloudOff: true}, false},
		{"no cloud configured", &spec.ProjectConfig{}, "", checkFlags{}, false},
		{"--cadence never submits", noID, url, checkFlags{cadence: "hourly"}, false},
		{"--cadences never submits", noID, url, checkFlags{cadences: []string{"quarterly"}}, false},
		{"--on-push never submits", noID, url, checkFlags{onPush: true}, false},
		{"--pr never submits", noID, url, checkFlags{pr: true}, false},
		{"--scheduled --cadence never submits", noID, url, checkFlags{scheduled: true, cadence: "hourly"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := missingProjectIDWarning(tc.cfg, &tc.flags, tc.cloudBase)
			if (got != "") != tc.want {
				t.Fatalf("warning = %q; want shown=%v", got, tc.want)
			}
			if tc.want {
				for _, s := range []string{"cloud.project_id", ".sigcomply.yaml", "SigComply dashboard", "next release"} {
					if !strings.Contains(got, s) {
						t.Errorf("warning %q does not mention %q", got, s)
					}
				}
			}
		})
	}
}
