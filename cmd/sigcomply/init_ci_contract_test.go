package cmd

// Semantic checks on the init-ci templates. The goldens pin the bytes;
// these pin what the bytes must agree with elsewhere in the product, so
// a change on either side fails here. Each guards a shipped bug:
//
//   - 0c59c10: the GitLab id_token was named SIGCOMPLY_OIDC_TOKEN while
//     the submitter read SIGCOMPLY_ID_TOKEN, so no GitLab run submitted.
//   - 7c88725: the templates downloaded a release asset goreleaser never
//     published.
//   - The per-cadence workflows submitted a different subset of policies
//     each to a dashboard that reads every run as the project's full
//     state; weekly and monthly ones evaluated zero policies.
//   - The install step extracted the release archive without checking it
//     against the release's checksums.txt, which install.sh verifies.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sigcomply/sigcomply-cli/internal/submitter"
)

// shippedTemplates returns every embedded init-ci template by path.
func shippedTemplates(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := fs.ReadFile(templatesFS, path)
		if err != nil {
			return err
		}
		out[path] = string(body)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 2 {
		t.Fatalf("found %d templates; want the GitHub set and the GitLab file", len(out))
	}
	return out
}

func TestInitCITemplates_GitLabIDTokenIsWhatTheSubmitterReads(t *testing.T) {
	body, err := fs.ReadFile(templatesFS, "templates/gitlab/.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]struct {
		IDTokens map[string]struct {
			Aud string `yaml:"aud"`
		} `yaml:"id_tokens"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse .gitlab-ci.yml: %v", err)
	}
	var found int
	for job, j := range doc {
		for name, tok := range j.IDTokens {
			found++
			if name != submitter.GitLabIDTokenEnv {
				t.Errorf("%s: id_tokens declares %s; the submitter reads %s", job, name, submitter.GitLabIDTokenEnv)
			}
			// GitLab mints the token before the CLI runs, so the CLI
			// cannot ask for its audience: the template must.
			if tok.Aud != submitter.DefaultAudience {
				t.Errorf("%s: id_tokens.%s.aud = %q; the dashboard validates %q", job, name, tok.Aud, submitter.DefaultAudience)
			}
		}
	}
	if found == 0 {
		t.Fatal(".gitlab-ci.yml declares no id_tokens; GitLab runs could never submit")
	}
	// The AWS web-identity step must read the same variable.
	if !strings.Contains(string(body), `"$`+submitter.GitLabIDTokenEnv+`"`) {
		t.Errorf(".gitlab-ci.yml never reads $%s", submitter.GitLabIDTokenEnv)
	}
}

// releaseBase matches the release download base in a template's install
// step; installAsset the archive name it derives from the version.
var (
	releaseBase  = regexp.MustCompile(`base="https://github\.com/SigComply/sigcomply-cli/releases/download/\$\{tag\}"`)
	installAsset = regexp.MustCompile(`asset="([^"]+)"`)
)

func TestInitCITemplates_DownloadAPublishedReleaseAsset(t *testing.T) {
	const version = "1.2.3"
	published := goreleaserArchiveName(t, version, "linux", "amd64")
	installer := installScriptAsset(t, "Linux", "x86_64", version)
	if published != installer {
		t.Fatalf("goreleaser publishes %q but install.sh downloads %q", published, installer)
	}
	for path, body := range shippedTemplates(t) {
		// The install step strips the v from the tag for the file name,
		// as goreleaser does for {{ .Version }}.
		if !strings.Contains(body, `ver="${tag#v}"`) {
			t.Errorf(`%s: install step does not derive ver="${tag#v}" from the tag`, path)
		}
		if n := len(releaseBase.FindAllString(body, -1)); n != 1 {
			t.Errorf("%s: %d release download bases; want 1", path, n)
		}
		m := installAsset.FindAllStringSubmatch(body, -1)
		if len(m) != 1 {
			t.Errorf("%s: %d asset names; want 1", path, len(m))
			continue
		}
		if got := strings.ReplaceAll(m[0][1], "${ver}", version); got != published {
			t.Errorf("%s: downloads %s; goreleaser publishes %s", path, got, published)
		}
		if !strings.Contains(body, `curl -fsSL "${base}/${asset}"`) {
			t.Errorf("%s: install step does not download ${base}/${asset}", path)
		}
	}
}

// installStep returns the lines of a template from the archive download
// to the extraction, in order.
func installStep(t *testing.T, path, body string) []string {
	t.Helper()
	var out []string
	in := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, `curl -fsSL "${base}/${asset}"`) {
			in = true
		}
		if in {
			out = append(out, trimmed)
		}
		if in && (strings.HasPrefix(trimmed, "tar ") || strings.HasPrefix(trimmed, "sudo tar ")) {
			break
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s: no install step found", path)
	}
	return out
}

// The install step must check the archive against the release's
// checksums.txt before extracting it, as install.sh does, and the check
// must reject a tampered or missing archive. The verification line is run
// for real against a matching and a tampered file.
func TestInitCITemplates_VerifyChecksumBeforeExtracting(t *testing.T) {
	if checksumName := goreleaserChecksumName(t); checksumName != "checksums.txt" {
		t.Fatalf(".goreleaser.yml publishes %q; the templates download checksums.txt", checksumName)
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum not on PATH")
	}
	bodies := shippedTemplates(t)
	// The hand-written examples are copied as-is, so they verify too.
	for _, p := range []string{"github-actions/basic.yml", "github-actions/multi-environment.yml", "gitlab-ci.yml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "examples", filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		bodies["examples/"+p] = string(b)
	}
	for path, body := range bodies {
		lines := installStep(t, path, body)
		verify := verifyLine(lines)
		if verify == "" {
			t.Errorf("%s: install step must download checksums.txt and run sha256sum -c before tar:\n%s", path, strings.Join(lines, "\n"))
			continue
		}
		runVerifyLine(t, path, verify)
	}
}

// verifyLine returns the install step's sha256sum line when the step
// downloads checksums.txt, verifies, then extracts, in that order; "" if
// not.
func verifyLine(lines []string) string {
	var verify string
	sawChecksums := false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, `curl -fsSL "${base}/checksums.txt"`):
			sawChecksums = true
		case strings.Contains(l, "sha256sum -c"):
			verify = l
		}
	}
	if !sawChecksums || !strings.Contains(lines[len(lines)-1], "tar -xzf") {
		return ""
	}
	return verify
}

// runVerifyLine runs a template's verification line against a matching
// and a tampered archive.
func runVerifyLine(t *testing.T, path, verify string) {
	t.Helper()
	// The snippet is written for /tmp; run it in a scratch directory.
	verify = strings.ReplaceAll(verify, "/tmp", "$WORK")
	for _, tc := range []struct {
		name    string
		content string
		wantOK  bool
	}{
		{"matching archive", "release bytes", true},
		{"tampered archive", "tampered bytes", false},
	} {
		dir := t.TempDir()
		const asset = "sigcomply_1.2.3_linux_amd64.tar.gz"
		sum := sha256.Sum256([]byte("release bytes"))
		if err := os.WriteFile(filepath.Join(dir, "checksums.txt"),
			[]byte(hex.EncodeToString(sum[:])+"  "+asset+"\n"+strings.Repeat("0", 64)+"  other.tar.gz\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, asset), []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), "sh", "-c", verify) //nolint:gosec // runs a line from our own committed template
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "WORK=" + dir, "asset=" + asset}
		out, err := cmd.CombinedOutput()
		if (err == nil) != tc.wantOK {
			t.Errorf("%s: %s: verification ok = %v; want %v\n%s", path, tc.name, err == nil, tc.wantOK, out)
		}
	}
}

// goreleaserChecksumName reads the checksum file name .goreleaser.yml
// publishes.
func goreleaserChecksumName(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Checksum struct {
			NameTemplate string `yaml:"name_template"`
		} `yaml:"checksum"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse .goreleaser.yml: %v", err)
	}
	return cfg.Checksum.NameTemplate
}

// goreleaserArchiveName renders the archive name_template from
// .goreleaser.yml, so the check follows the real release config.
func goreleaserArchiveName(t *testing.T, version, goos, goarch string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		ProjectName string `yaml:"project_name"`
		Archives    []struct {
			NameTemplate string   `yaml:"name_template"`
			Formats      []string `yaml:"formats"`
		} `yaml:"archives"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse .goreleaser.yml: %v", err)
	}
	if len(cfg.Archives) != 1 || len(cfg.Archives[0].Formats) != 1 {
		t.Fatalf(".goreleaser.yml: want one archive with one default format; update this test if that changed")
	}
	tmpl, err := template.New("name").Parse(cfg.Archives[0].NameTemplate)
	if err != nil {
		t.Fatalf("name_template: %v", err)
	}
	var b strings.Builder
	data := map[string]string{"ProjectName": cfg.ProjectName, "Version": version, "Os": goos, "Arch": goarch, "Arm": ""}
	if err := tmpl.Execute(&b, data); err != nil {
		t.Fatalf("name_template: %v", err)
	}
	return b.String() + "." + cfg.Archives[0].Formats[0]
}

// installScriptAsset asks scripts/install.sh which archive it downloads.
func installScriptAsset(t *testing.T, unameS, unameM, version string) string {
	t.Helper()
	if runtime.GOOS == goosWindows {
		t.Skip("install.sh needs a POSIX shell")
	}
	cmd := exec.CommandContext(context.Background(), "sh", "-c", `. ./install.sh && asset_name "$1" "$2" "$3"`, "sh", unameS, unameM, version) //nolint:gosec // #nosec G204 -- fixed script; the arguments are positional parameters, never parsed as shell
	cmd.Dir = filepath.Join("..", "..", "scripts")
	cmd.Env = append(os.Environ(), "SIGCOMPLY_INSTALL_LIB=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh asset_name: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

var cronLine = regexp.MustCompile(`(?m)^\s*-\s*cron:\s*'([^']+)'`)

// Every submitted run must be a full snapshot, and a manual policy's
// folder must be read inside every calendar window of its cadence. So the
// scaffold has exactly one scheduled workflow, it fires every day and
// runs `check --scheduled`, and every other check is `--pr`, which never
// submits.
func TestInitCITemplates_OneDailyScheduledRunAndPRChecks(t *testing.T) {
	scheduled := 0
	for path, body := range shippedTemplates(t) {
		for _, m := range ciCommand.FindAllStringSubmatch(body, -1) {
			if !isScaffoldedCheck(m[1]) {
				t.Errorf("%s: runs `sigcomply %s`; want only %s or %s", path, m[1], scaffoldedScheduledCheck, scaffoldedPRCheck)
			}
		}
		if strings.Contains(body, "CADENCE") {
			t.Errorf("%s: still refers to the removed CADENCE variable", path)
		}
		// GitLab schedules are created by the customer.
		if strings.HasPrefix(path, "templates/github/") && checkDailyCron(t, path, body) {
			scheduled++
		}
	}
	if scheduled != 1 {
		t.Errorf("%d GitHub templates have a cron; want exactly one", scheduled)
	}
	checkGitLabScheduledJob(t)
}

// checkDailyCron reports whether a GitHub template has a cron, and checks
// that every cron fires daily and the workflow runs `check --scheduled`.
func checkDailyCron(t *testing.T, path, body string) bool {
	t.Helper()
	crons := cronLine.FindAllStringSubmatch(body, -1)
	if len(crons) == 0 {
		return false
	}
	if !strings.Contains(body, "sigcomply "+scaffoldedScheduledCheck) {
		t.Errorf("%s: has a cron but does not run `%s`", path, scaffoldedScheduledCheck)
	}
	for _, c := range crons {
		if n := len(cronFirings(t, c[1], 2027, 2027)); n != 365 {
			t.Errorf("%s: cron %q fires %d days in 2027; want every day", path, c[1], n)
		}
	}
	return true
}

// checkGitLabScheduledJob checks the GitLab scheduled job runs on every
// pipeline schedule and starts with `check --scheduled`.
func checkGitLabScheduledJob(t *testing.T) {
	t.Helper()
	body, err := fs.ReadFile(templatesFS, "templates/gitlab/.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]struct {
		Rules []struct {
			If string `yaml:"if"`
		} `yaml:"rules"`
		Script []string `yaml:"script"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	job, ok := doc["compliance:scheduled"]
	if !ok || len(job.Rules) != 1 || job.Rules[0].If != `$CI_PIPELINE_SOURCE == "schedule"` {
		t.Errorf("compliance:scheduled must run on every pipeline schedule; got %+v", job.Rules)
	}
	if len(job.Script) == 0 || job.Script[0] != "sigcomply "+scaffoldedScheduledCheck {
		t.Errorf("compliance:scheduled script = %v; want sigcomply check --scheduled first", job.Script)
	}
}

// cronFirings lists every UTC time in [fromYear, toYear] a five-field
// cron expression fires. It supports what the templates use: numbers,
// comma lists and `*`.
func cronFirings(t *testing.T, expr string, fromYear, toYear int) []time.Time {
	t.Helper()
	f := strings.Fields(expr)
	if len(f) != 5 {
		t.Fatalf("cron %q: want 5 fields", expr)
	}
	minute, hour := cronField(t, f[0]), cronField(t, f[1])
	dom, month, dow := cronField(t, f[2]), cronField(t, f[3]), cronField(t, f[4])
	if minute == nil || hour == nil || len(minute) != 1 || len(hour) != 1 {
		t.Fatalf("cron %q: minute and hour must be single values", expr)
	}
	var out []time.Time
	for d := time.Date(fromYear, 1, 1, 0, 0, 0, 0, time.UTC); d.Year() <= toYear; d = d.AddDate(0, 0, 1) {
		if !cronMatch(month, int(d.Month())) {
			continue
		}
		// Standard cron: when both day fields are restricted, either may match.
		domOK, dowOK := cronMatch(dom, d.Day()), cronMatch(dow, int(d.Weekday()))
		switch {
		case dom != nil && dow != nil && !domOK && !dowOK,
			dom == nil && !dowOK,
			dow == nil && !domOK:
			continue
		}
		out = append(out, d.Add(time.Duration(hour[0])*time.Hour+time.Duration(minute[0])*time.Minute))
	}
	return out
}

// cronField parses one field; nil means `*`.
func cronField(t *testing.T, s string) []int {
	t.Helper()
	if s == "*" {
		return nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(part)
		if err != nil {
			t.Fatalf("cron field %q: only numbers, lists and * are supported (%v)", s, err)
		}
		out = append(out, n)
	}
	return out
}

func cronMatch(allowed []int, v int) bool {
	if allowed == nil {
		return true
	}
	for _, a := range allowed {
		if a == v {
			return true
		}
	}
	return false
}
