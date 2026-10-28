package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// isoFW is the ISO 27001 identifier — bound here so the goconst linter
// doesn't trip on the repeated literal across the cmd test files.
const (
	isoFW = "iso27001"
	// testAWSRegion is the AWS region used by the source-banner and
	// vault-region fixtures.
	testAWSRegion = "us-east-1"
	// testBinaryName is argv[0] as the CLI sees it.
	testBinaryName = "sigcomply"
)

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
	if cfg.Vault.Backend != backendLocal {
		t.Errorf("Vault.Backend = %q; want local", cfg.Vault.Backend)
	}
	// aws.iam is the active example source.
	if _, ok := cfg.Sources["aws.iam"]; !ok {
		t.Errorf("expected aws.iam in scaffolded sources, got %v", cfg.Sources)
	}
	// manual.pdf must be scaffolded too: the framework ships manual-evidence
	// policies, and without a manual.pdf source they error (source not
	// registered) rather than reporting fail. See init.go starterConfig.
	if _, ok := cfg.Sources["manual.pdf"]; !ok {
		t.Errorf("expected manual.pdf in scaffolded sources, got %v", cfg.Sources)
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

// An ISO 27001 scaffold must not tell the operator to run a command that
// exits 3. init-ci accepts only soc2, but its workflows read the
// framework from the config, so the next step names the --framework soc2
// form that works rather than a bare command that fails.
func TestInit_Iso27001NextStepsNameWorkingInitCI(t *testing.T) {
	var out bytes.Buffer
	if err := runInit(&out, initFlags{framework: isoFW, out: filepath.Join(t.TempDir(), "cfg.yaml")}); err != nil {
		t.Fatalf("runInit(iso27001): %v", err)
	}
	got := out.String()
	if strings.Contains(got, "sigcomply init-ci --ci github`") {
		t.Errorf("iso27001 next steps recommend bare init-ci, which rejects iso27001 with exit 3:\n%s", got)
	}
	if !strings.Contains(got, "sigcomply init-ci --ci github --framework soc2") {
		t.Errorf("next steps should name init-ci --framework soc2; got:\n%s", got)
	}
	if strings.Contains(got, "v1-alpha") {
		t.Errorf("next steps use internal release jargon:\n%s", got)
	}
}

// A local run writes hundreds of vault files; init points at the ignore
// rule unless the project already has one.
func TestInit_GitignoreHint(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := runInit(&out, initFlags{framework: defaultFW, out: filepath.Join(dir, ".sigcomply.yaml")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), ".sigcomply/vault/") {
		t.Errorf("init should suggest ignoring the local vault; got:\n%s", out.String())
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".sigcomply/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runInit(&out, initFlags{framework: defaultFW, out: filepath.Join(dir, ".sigcomply.yaml"), force: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), ".gitignore") {
		t.Errorf("hint printed although .gitignore already covers the vault:\n%s", out.String())
	}
}

// Enabling every AWS service must be a matter of uncommenting lines: the
// scaffold names every registered aws.* source, active or commented.
func TestStarterConfig_ListsEveryAWSSource(t *testing.T) {
	body := starterConfig(defaultFW)
	for _, id := range sources.IDs() {
		if !strings.HasPrefix(id, "aws.") {
			continue
		}
		if !strings.Contains(body, "\n  "+id+":") && !strings.Contains(body, "\n  # "+id+":") {
			t.Errorf("starter config does not list %s", id)
		}
	}
}

// The commented parameters example must not be one that fails on every
// shipped policy, and uncommenting the AWS lines must still validate.
func TestStarterConfig_ExamplesValidate(t *testing.T) {
	body := starterConfig(defaultFW)
	if strings.Contains(body, "max_age_days") {
		t.Error("parameters example names max_age_days, which no shipped policy declares")
	}
	uncommented := strings.ReplaceAll(body, "  # aws.", "  aws.")
	cfg, err := spec.LoadProjectConfig([]byte(uncommented))
	if err != nil {
		t.Fatalf("scaffold with every AWS source uncommented does not validate: %v", err)
	}
	for id := range cfg.Sources {
		if strings.HasPrefix(id, "aws.") {
			if _, ok := sources.Lookup(id); !ok {
				t.Errorf("scaffold lists unknown source %s", id)
			}
		}
	}
}

// The soc2 path is the one where the recommendation is correct, so it
// must keep it — the guard above must not silence both.
func TestInit_Soc2NextStepsRecommendInitCI(t *testing.T) {
	var out bytes.Buffer
	if err := runInit(&out, initFlags{framework: "soc2", out: filepath.Join(t.TempDir(), "cfg.yaml")}); err != nil {
		t.Fatalf("runInit(soc2): %v", err)
	}
	if got := out.String(); !strings.Contains(got, "sigcomply init-ci --ci github") {
		t.Errorf("soc2 next steps should recommend init-ci; got:\n%s", got)
	}
}

// The commented cloud block must point at the host that serves
// /api/v1/runs. api.sigcomply.com is only the OIDC audience string; it
// does not resolve.
func TestInit_CloudBaseURLComment(t *testing.T) {
	for _, fw := range []string{defaultFW, isoFW} {
		body := starterConfig(fw)
		if !strings.Contains(body, "#   base_url: https://sigcomply.com\n") {
			t.Errorf("%s scaffold: commented cloud.base_url should be https://sigcomply.com", fw)
		}
		if strings.Contains(body, "base_url: https://api.sigcomply.com") {
			t.Errorf("%s scaffold: base_url must not be the OIDC audience https://api.sigcomply.com", fw)
		}
	}
}

// The scaffold lands in the user's repo, where a relative docs path
// points nowhere. It must link the published reference.
func TestStarterConfig_LinksPublishedReference(t *testing.T) {
	body := starterConfig("soc2")
	const want = "https://github.com/SigComply/sigcomply-cli/blob/main/docs/configuration.md"
	if !strings.Contains(body, want) {
		t.Errorf("starter config should link %s", want)
	}
}
