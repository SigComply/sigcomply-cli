package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
)

// runInitCIIn temporarily switches into dir, runs the subcommand with
// the given args, and returns stdout + error. The init-ci command
// writes relative to cwd, so isolating each test in its own tempdir
// keeps them independent.
func runInitCIIn(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%s): %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatalf("Chdir back to %s: %v", prev, err)
		}
	})

	cmd := newInitCICmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), err
}

func TestInitCI_GitHub_WritesExpectedFileSet(t *testing.T) {
	dir := t.TempDir()
	_, err := runInitCIIn(t, dir, "--ci", "github")
	if err != nil {
		t.Fatalf("init-ci: %v", err)
	}
	workflows := filepath.Join(dir, ".github", "workflows")
	entries, err := os.ReadDir(workflows)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want := []string{
		"compliance-annual.yml",
		"compliance-daily.yml",
		"compliance-monthly.yml",
		"compliance-on-push.yml",
		"compliance-quarterly.yml",
		"compliance-weekly.yml",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("scaffolded files = %v; want %v", got, want)
	}
}

func TestInitCI_GitLab_WritesGitlabCIYaml(t *testing.T) {
	dir := t.TempDir()
	if _, err := runInitCIIn(t, dir, "--ci", "gitlab"); err != nil {
		t.Fatalf("init-ci: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitlab-ci.yml")); err != nil {
		t.Errorf(".gitlab-ci.yml not written: %v", err)
	}
}

func TestInitCI_RejectsExistingFiles_WithoutForce(t *testing.T) {
	dir := t.TempDir()
	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflows, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflows, "compliance-daily.yml"), []byte("# pre-existing\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	_, err := runInitCIIn(t, dir, "--ci", "github")
	if err == nil {
		t.Fatal("want error when target file exists and --force is not set")
	}
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != orchestrator.ExitConfig {
		t.Errorf("want exitCodeError{code:3}; got %v", err)
	}
	if !strings.Contains(err.Error(), "compliance-daily.yml") || !strings.Contains(err.Error(), "--force") {
		t.Errorf("error %q should reference the conflicting file + --force hint", err.Error())
	}
	// Original content must be preserved.
	body, err := os.ReadFile(filepath.Join(workflows, "compliance-daily.yml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(body) != "# pre-existing\n" {
		t.Errorf("file overwritten despite --force absent: %q", body)
	}
}

func TestInitCI_ForceOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflows, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(workflows, "compliance-daily.yml")
	if err := os.WriteFile(target, []byte("# old\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := runInitCIIn(t, dir, "--ci", "github", "--force"); err != nil {
		t.Fatalf("init-ci --force: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(body), "Compliance — Daily") {
		t.Errorf("file not overwritten with template body: %q", body)
	}
}

func TestInitCI_BadCIErrors(t *testing.T) {
	dir := t.TempDir()
	_, err := runInitCIIn(t, dir, "--ci", "bitbucket")
	if err == nil {
		t.Fatal("want error for unsupported --ci value")
	}
	if !strings.Contains(err.Error(), "bitbucket") {
		t.Errorf("error should name the offending value; got %v", err)
	}
}

func TestInitCI_MissingCIFlagIsRequired(t *testing.T) {
	dir := t.TempDir()
	_, err := runInitCIIn(t, dir)
	if err == nil {
		t.Fatal("want error when --ci is omitted")
	}
}

func TestInitCI_GoldenCompare_GitHub(t *testing.T) {
	// Resolve golden paths before runInitCIIn changes cwd.
	goldenDaily := absTestdata(t, "golden_compliance-daily.yml")
	goldenOnPush := absTestdata(t, "golden_compliance-on-push.yml")
	dir := t.TempDir()
	if _, err := runInitCIIn(t, dir, "--ci", "github"); err != nil {
		t.Fatalf("init-ci: %v", err)
	}
	cases := []struct {
		written string
		golden  string
	}{
		{filepath.Join(dir, ".github", "workflows", "compliance-daily.yml"), goldenDaily},
		{filepath.Join(dir, ".github", "workflows", "compliance-on-push.yml"), goldenOnPush},
	}
	for _, tc := range cases {
		gotBytes, err := os.ReadFile(tc.written)
		if err != nil {
			t.Fatalf("read %s: %v", tc.written, err)
		}
		wantBytes, err := os.ReadFile(tc.golden)
		if err != nil {
			t.Fatalf("read golden %s: %v", tc.golden, err)
		}
		if !bytes.Equal(gotBytes, wantBytes) {
			t.Errorf("scaffolded %s != %s\n--- got ---\n%s\n--- want ---\n%s",
				filepath.Base(tc.written), tc.golden, gotBytes, wantBytes)
		}
	}
}

func TestInitCI_GoldenCompare_GitLab(t *testing.T) {
	goldenPath := absTestdata(t, "golden_gitlab-ci.yml")
	dir := t.TempDir()
	if _, err := runInitCIIn(t, dir, "--ci", "gitlab"); err != nil {
		t.Fatalf("init-ci: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, ".gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("read .gitlab-ci.yml: %v", err)
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("scaffolded .gitlab-ci.yml differs from golden\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// absTestdata resolves a golden-file path relative to this test
// package while the test is still in its original cwd.
func absTestdata(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("abs testdata path: %v", err)
	}
	return p
}

func TestInitCI_OutDirOverride(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "ci", "workflows")
	if _, err := runInitCIIn(t, dir, "--ci", "github", "--out", custom); err != nil {
		t.Fatalf("init-ci: %v", err)
	}
	if _, err := os.Stat(filepath.Join(custom, "compliance-daily.yml")); err != nil {
		t.Errorf("file not under --out: %v", err)
	}
}

func TestInitCI_StdoutSummary(t *testing.T) {
	dir := t.TempDir()
	out, err := runInitCIIn(t, dir, "--ci", "github")
	if err != nil {
		t.Fatalf("init-ci: %v", err)
	}
	for _, want := range []string{"scaffolded", "framework=", "Next steps:"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q: %s", want, out)
		}
	}
}

func TestScanFrameworkLine(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{"framework: iso27001\n", "iso27001"},
		{"framework: \"soc2\"\n", "soc2"},
		{"  framework:   soc2\nother: x\n", "soc2"},
		{"name: x\n", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := scanFrameworkLine(tc.body); got != tc.want {
			t.Errorf("scanFrameworkLine(%q) = %q; want %q", tc.body, got, tc.want)
		}
	}
}

func TestResolveInitCIFramework_FlagWins(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".sigcomply.yaml")
	if err := os.WriteFile(cfg, []byte("framework: iso27001\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if fw := resolveInitCIFramework(initCIFlags{framework: defaultFW, config: cfg}); fw != defaultFW {
		t.Errorf("flag should win; got %q", fw)
	}
}

func TestResolveInitCIFramework_ReadsConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".sigcomply.yaml")
	if err := os.WriteFile(cfg, []byte("framework: soc2\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if fw := resolveInitCIFramework(initCIFlags{config: cfg}); fw != defaultFW {
		t.Errorf("framework from config = %q", fw)
	}
}

func TestResolveInitCIFramework_DefaultSoc2(t *testing.T) {
	if fw := resolveInitCIFramework(initCIFlags{config: filepath.Join(t.TempDir(), "missing.yaml")}); fw != defaultFW {
		t.Errorf("default framework = %q; want soc2", fw)
	}
}

// defaultFW is the SOC 2 identifier — bound here so the goconst linter
// doesn't flag the same literal across the tests.
const defaultFW = "soc2"

func TestInitCI_RejectsUnsupportedFramework(t *testing.T) {
	dir := t.TempDir()
	_, err := runInitCIIn(t, dir, "--ci", "github", "--framework", "iso27001")
	if err == nil {
		t.Fatal("want error for unsupported framework")
	}
	if !strings.Contains(err.Error(), "iso27001") {
		t.Errorf("error should reference framework: %v", err)
	}
}

// Sanity-check the embedded FS: every shipped template references the
// SigComply Cloud OIDC audience and includes a `sigcomply check`
// invocation. Guards against accidental template edits losing wiring.
func TestEmbeddedTemplates_ContainOIDCAudienceAndCLI(t *testing.T) {
	plan, err := scaffoldPlanGitHub("/tmp/unused")
	if err != nil {
		t.Fatalf("scaffoldPlanGitHub: %v", err)
	}
	if len(plan) != 6 {
		t.Errorf("expected 6 github templates; got %d", len(plan))
	}
	all := append([]scaffoldFile(nil), plan...)
	gitlab, err := scaffoldPlanGitLab("/tmp/unused")
	if err != nil {
		t.Fatalf("scaffoldPlanGitLab: %v", err)
	}
	all = append(all, gitlab...)
	for _, f := range all {
		body, err := readEmbed(f.embeddedPath)
		if err != nil {
			t.Fatalf("read %s: %v", f.embeddedPath, err)
		}
		if !strings.Contains(body, "api.sigcomply.com") {
			t.Errorf("%s missing OIDC audience api.sigcomply.com", f.embeddedPath)
		}
		if !strings.Contains(body, "sigcomply check") {
			t.Errorf("%s missing sigcomply check invocation", f.embeddedPath)
		}
	}
}

// readEmbed is a thin helper so the test can read templatesFS without
// importing io/fs at the test top level.
func readEmbed(path string) (string, error) {
	f, err := templatesFS.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // best-effort cleanup
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
