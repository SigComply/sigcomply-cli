package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
	"gopkg.in/yaml.v3"
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
	_, err := runInitCIIn(t, dir, "--ci", ciGitHub)
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
	_, err := runInitCIIn(t, dir, "--ci", ciGitHub)
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
	if _, err := runInitCIIn(t, dir, "--ci", ciGitHub, "--force"); err != nil {
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
	// A missing required flag is a configuration error → exit 3, not
	// cobra's default exit 2.
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != orchestrator.ExitConfig {
		t.Errorf("want ExitConfig (3) for missing --ci; got %v", err)
	}
}

func TestInitCI_GoldenCompare_GitHub(t *testing.T) {
	// Resolve golden paths before runInitCIIn changes cwd.
	goldenDaily := absTestdata(t, "golden_compliance-daily.yml")
	goldenOnPush := absTestdata(t, "golden_compliance-on-push.yml")
	setCLIVersionForTest(t, goldenVersion)
	dir := t.TempDir()
	if _, err := runInitCIIn(t, dir, "--ci", ciGitHub); err != nil {
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
	setCLIVersionForTest(t, goldenVersion)
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

// goldenVersion is the build version the golden files are rendered
// with, so they don't change on every release.
const goldenVersion = "1.2.3"

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
	if _, err := runInitCIIn(t, dir, "--ci", ciGitHub, "--out", custom); err != nil {
		t.Fatalf("init-ci: %v", err)
	}
	if _, err := os.Stat(filepath.Join(custom, "compliance-daily.yml")); err != nil {
		t.Errorf("file not under --out: %v", err)
	}
}

func TestInitCI_StdoutSummary(t *testing.T) {
	dir := t.TempDir()
	out, err := runInitCIIn(t, dir, "--ci", ciGitHub)
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
		{"framework: iso27001\n", isoFW},
		{"framework: \"soc2\"\n", defaultFW},
		{"  framework:   soc2\nother: x\n", defaultFW},
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

// defaultFW is the SOC 2 identifier — aliased to the production constant
// so there is a single "soc2" literal in the package.
const defaultFW = defaultFramework

func TestInitCI_RejectsUnsupportedFramework(t *testing.T) {
	dir := t.TempDir()
	_, err := runInitCIIn(t, dir, "--ci", ciGitHub, "--framework", isoFW)
	if err == nil {
		t.Fatal("want error for unsupported framework")
	}
	if !strings.Contains(err.Error(), isoFW) {
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

// setCLIVersionForTest pins the build version init-ci renders into the
// scaffold, and restores it when the test ends.
func setCLIVersionForTest(t *testing.T, v string) {
	t.Helper()
	prev := cliVersion
	cliVersion = v
	t.Cleanup(func() { cliVersion = prev })
}

// releaseTag is a sample clean release version.
const releaseTag = "v0.88.4"

func TestScaffoldVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"0.88.4", releaseTag},                      // goreleaser {{.Version}}: no "v"
		{releaseTag, releaseTag},                    // make build on a tagged commit
		{"v10.0.12", "v10.0.12"},                    // multi-digit parts
		{"dev", versionLatest},                      // go build without ldflags
		{"", versionLatest},                         // defensive
		{"v0.88.3-4-gabc1234", versionLatest},       // git describe past a tag
		{"v0.88.3-4-gabc1234-dirty", versionLatest}, // dirty tree
		{"v0.88.4-dirty", versionLatest},            // dirty tree on a tag
		{"45c25e3", versionLatest},                  // git describe --always, no tags
		{"v1.2", versionLatest},                     // not a full semver
		{"v01.2.3", versionLatest},                  // leading zero is not semver
		{"v1.2.3 ", versionLatest},                  // stray whitespace
	}
	for _, tc := range cases {
		if got := scaffoldVersion(tc.in); got != tc.want {
			t.Errorf("scaffoldVersion(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// readScaffold runs init-ci for ci into a fresh dir and returns every
// written file's body keyed by base name.
func readScaffold(t *testing.T, ci string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	if _, err := runInitCIIn(t, dir, "--ci", ci); err != nil {
		t.Fatalf("init-ci --ci %s: %v", ci, err)
	}
	root := dir
	if ci == ciGitHub {
		root = filepath.Join(dir, ".github", "workflows")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(b)
	}
	if len(out) == 0 {
		t.Fatalf("init-ci --ci %s wrote no files", ci)
	}
	return out
}

// versionLine matches the SIGCOMPLY_VERSION assignment in either CI's
// syntax (GitHub env: unquoted, GitLab variables: double-quoted).
var versionLine = regexp.MustCompile(`(?m)^\s*SIGCOMPLY_VERSION:\s*"?([^"\s#]+)"?`)

func TestInitCI_RendersReleaseVersion(t *testing.T) {
	for _, ci := range supportedCIs {
		t.Run(ci, func(t *testing.T) {
			setCLIVersionForTest(t, "0.91.2")
			for name, body := range readScaffold(t, ci) {
				m := versionLine.FindStringSubmatch(body)
				if m == nil {
					t.Errorf("%s: no SIGCOMPLY_VERSION line", name)
					continue
				}
				if m[1] != "v0.91.2" {
					t.Errorf("%s: SIGCOMPLY_VERSION = %q; want v0.91.2 (the running binary's release)", name, m[1])
				}
				if strings.Contains(body, scaffoldVersionPlaceholder) {
					t.Errorf("%s: placeholder %q left unrendered", name, scaffoldVersionPlaceholder)
				}
			}
		})
	}
}

func TestInitCI_DevBuildRendersLatest(t *testing.T) {
	for _, ci := range supportedCIs {
		t.Run(ci, func(t *testing.T) {
			setCLIVersionForTest(t, "v0.88.3-4-gabc1234-dirty")
			for name, body := range readScaffold(t, ci) {
				m := versionLine.FindStringSubmatch(body)
				if len(m) < 2 || m[1] != versionLatest {
					t.Errorf("%s: SIGCOMPLY_VERSION = %v; want latest for a non-release build", name, m)
				}
				// The install step must resolve "latest" itself.
				if !strings.Contains(body, `if [ "$version" = "latest" ]`) {
					t.Errorf("%s: install step does not handle SIGCOMPLY_VERSION=latest", name)
				}
			}
		})
	}
}

func TestInitCI_StdoutVersionGuidance(t *testing.T) {
	setCLIVersionForTest(t, "v0.91.2")
	out, err := runInitCIIn(t, t.TempDir(), "--ci", ciGitHub)
	if err != nil {
		t.Fatalf("init-ci: %v", err)
	}
	if !strings.Contains(out, "v0.91.2") {
		t.Errorf("stdout should name the pinned version v0.91.2: %s", out)
	}

	setCLIVersionForTest(t, "dev")
	out, err = runInitCIIn(t, t.TempDir(), "--ci", ciGitHub)
	if err != nil {
		t.Fatalf("init-ci: %v", err)
	}
	if !strings.Contains(out, `"latest"`) || !strings.Contains(out, "pin") {
		t.Errorf("stdout for a dev build should say the scaffold tracks \"latest\" and suggest pinning: %s", out)
	}
}

// Cloud submission only happens when cloud.base_url is set, so the
// next steps must say so; the OIDC audience is a fixed identifier.
func TestInitCI_StdoutMentionsCloudBaseURL(t *testing.T) {
	for _, ci := range supportedCIs {
		out, err := runInitCIIn(t, t.TempDir(), "--ci", ci)
		if err != nil {
			t.Fatalf("init-ci --ci %s: %v", ci, err)
		}
		for _, want := range []string{"cloud.base_url", "https://sigcomply.com", "https://api.sigcomply.com"} {
			if !strings.Contains(out, want) {
				t.Errorf("--ci %s stdout missing %q:\n%s", ci, want, out)
			}
		}
	}
}

// The GitLab job must hand the AWS SDK a web-identity token: AWS_ROLE_ARN
// alone gives the default credential chain nothing to assume the role with.
func TestInitCI_GitLabWiresAWSWebIdentity(t *testing.T) {
	body := readScaffold(t, ciGitLab)[".gitlab-ci.yml"]
	for _, want := range []string{
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_ROLE_ARN",
		`"$SIGCOMPLY_ID_TOKEN" >`,
		"aud: https://api.sigcomply.com",
	} {
		if !strings.Contains(body, want) {
			t.Errorf(".gitlab-ci.yml missing %q", want)
		}
	}
	if !strings.Contains(body, "export AWS_WEB_IDENTITY_TOKEN_FILE") {
		t.Error(".gitlab-ci.yml must export AWS_WEB_IDENTITY_TOKEN_FILE so the CLI process sees it")
	}
	// Keep the token out of the job log.
	for _, bad := range []string{"echo $SIGCOMPLY_ID_TOKEN", `echo "$SIGCOMPLY_ID_TOKEN"`, "set -x", "cat \"$AWS_WEB_IDENTITY_TOKEN_FILE\""} {
		if strings.Contains(body, bad) {
			t.Errorf(".gitlab-ci.yml contains %q, which would print the token", bad)
		}
	}
	// Header must not cite a doc that does not exist or promise cron comments.
	if strings.Contains(body, "10-ci-execution-model") {
		t.Error(".gitlab-ci.yml header cites docs/architecture/10-ci-execution-model.md, which does not exist")
	}
	if strings.Contains(body, "example cron") {
		t.Error(".gitlab-ci.yml header refers to cron comments it does not contain")
	}
}

// The hand-written examples under examples/ are copied by users as-is, so
// they must not carry a pinned release that silently goes stale, and the
// GitLab one must give the AWS SDK the same web-identity wiring as the
// init-ci template.
func TestExamples_InstallLatestAndWireAWS(t *testing.T) {
	root := filepath.Join("..", "..", "examples")
	files := []string{
		filepath.Join(root, "github-actions", "basic.yml"),
		filepath.Join(root, "github-actions", "multi-environment.yml"),
		filepath.Join(root, "gitlab-ci.yml"),
	}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		body := string(b)
		m := versionLine.FindStringSubmatch(body)
		if len(m) < 2 || m[1] != versionLatest {
			t.Errorf("%s: SIGCOMPLY_VERSION = %v; want latest (with a comment on pinning)", p, m)
		}
		if !strings.Contains(body, "Pin a release tag") {
			t.Errorf("%s: missing the comment telling users to pin a release", p)
		}
		if !strings.Contains(body, "cloud.base_url") {
			t.Errorf("%s: should say cloud submission needs cloud.base_url", p)
		}
		if strings.Contains(body, "fail_on_violation: true") {
			t.Errorf("%s: ci.fail_on_violation already defaults to true", p)
		}
	}
	gl, err := os.ReadFile(filepath.Join(root, "gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("read gitlab example: %v", err)
	}
	if !strings.Contains(string(gl), "export AWS_WEB_IDENTITY_TOKEN_FILE") {
		t.Error("examples/gitlab-ci.yml must export AWS_WEB_IDENTITY_TOKEN_FILE")
	}
}

// webIdentitySnippet returns the before_script entry of a GitLab pipeline
// that writes the AWS web-identity token file.
func webIdentitySnippet(t *testing.T, pipeline []byte) string {
	t.Helper()
	var doc map[string]struct {
		BeforeScript []string `yaml:"before_script"`
	}
	if err := yaml.Unmarshal(pipeline, &doc); err != nil {
		t.Fatalf("parse pipeline: %v", err)
	}
	for _, step := range doc[".sigcomply_base"].BeforeScript {
		if strings.Contains(step, "AWS_WEB_IDENTITY_TOKEN_FILE") {
			return step
		}
	}
	t.Fatal(".sigcomply_base before_script has no AWS_WEB_IDENTITY_TOKEN_FILE step")
	return ""
}

// The token file must be exported only when a role is configured. A set
// AWS_WEB_IDENTITY_TOKEN_FILE outranks the SDK's instance-role fallback and
// fails with "role ARN is not set", so a runner that reaches an S3 vault
// through its instance role would lose its credentials.
func TestGitLabWebIdentity_ExportedOnlyWithRoleARN(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	example, err := os.ReadFile(filepath.Join("..", "..", "examples", "gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	pipelines := map[string][]byte{
		"init-ci template":       []byte(readScaffold(t, ciGitLab)[".gitlab-ci.yml"]),
		"examples/gitlab-ci.yml": example,
	}
	for name, body := range pipelines {
		snippet := webIdentitySnippet(t, body)
		for _, tc := range []struct {
			roleARN    string
			wantExport bool
		}{
			{"arn:aws:iam::000000000000:role/test", true},
			{"", false},
		} {
			cmd := exec.CommandContext(t.Context(), "sh", "-c", snippet+"\nprintf '%s' \"${AWS_WEB_IDENTITY_TOKEN_FILE:-}\"") //nolint:gosec // runs a snippet from our own committed template
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "TMPDIR=" + t.TempDir(),
				"SIGCOMPLY_ID_TOKEN=test-token", "AWS_ROLE_ARN=" + tc.roleARN}
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("%s: run snippet: %v", name, err)
			}
			if got := len(out) > 0; got != tc.wantExport {
				t.Errorf("%s: AWS_ROLE_ARN=%q exported token file = %v, want %v", name, tc.roleARN, got, tc.wantExport)
			}
		}
	}
}
