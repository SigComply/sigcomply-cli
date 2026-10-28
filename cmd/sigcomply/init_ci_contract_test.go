package cmd

// Semantic checks on the init-ci templates. The goldens pin the bytes;
// these pin what the bytes must agree with elsewhere in the product, so
// a change on either side fails here. Each guards a shipped bug:
//
//   - 0c59c10: the GitLab id_token was named SIGCOMPLY_OIDC_TOKEN while
//     the submitter read SIGCOMPLY_ID_TOKEN, so no GitLab run submitted.
//   - 7c88725: the templates downloaded a release asset goreleaser never
//     published.
//   - 8fc0662: the quarterly and annual crons fired on the first day of a
//     period, so a push in the hours before the run moved HEAD into a
//     period whose manual-evidence folder could not hold anything yet.

import (
	"context"
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

	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
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

// releaseURL matches the archive download in a template's install step.
var releaseURL = regexp.MustCompile(`https://github\.com/SigComply/sigcomply-cli/releases/download/([^"\s]+)`)

func TestInitCITemplates_DownloadAPublishedReleaseAsset(t *testing.T) {
	const tag, version = "v1.2.3", "1.2.3"
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
		m := releaseURL.FindAllStringSubmatch(body, -1)
		if len(m) != 1 {
			t.Errorf("%s: %d release download URLs; want 1", path, len(m))
			continue
		}
		rel := strings.NewReplacer("${tag}", tag, "${ver}", version).Replace(m[0][1])
		if want := tag + "/" + published; rel != want {
			t.Errorf("%s: downloads releases/download/%s; goreleaser publishes releases/download/%s", path, rel, want)
		}
	}
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

// cadenceCron pairs a GitHub template's cron with the cadence its
// `sigcomply check --cadence` step runs.
var (
	cronLine     = regexp.MustCompile(`(?m)^\s*-\s*cron:\s*'([^']+)'`)
	cadenceCheck = regexp.MustCompile(`(?m)sigcomply check --cadence (\w+)`)
)

// TestInitCITemplates_SupraMonthlyCronsFireInsideThePeriod checks every
// firing of the monthly, quarterly and annual crons over several years
// lands at least a day after the start of both the run's period
// (planner.DerivePeriod) and the cadence's evidence folder period
// (planner.CadencePeriod). Daily and weekly runs are exempt: no manual
// evidence entry has a daily or weekly cadence, so their folders never
// gate a manual check, and a daily cron cannot avoid a boundary.
func TestInitCITemplates_SupraMonthlyCronsFireInsideThePeriod(t *testing.T) {
	checked := map[string]bool{}
	for path, body := range shippedTemplates(t) {
		if !strings.HasPrefix(path, "templates/github/") {
			continue // GitLab schedules are created by the customer
		}
		cad := cadenceCheck.FindStringSubmatch(body)
		if cad == nil {
			continue
		}
		switch cadence := cad[1]; cadence {
		case "monthly", "quarterly", "annual":
			checkCronsInsidePeriod(t, path, body, cadence)
			checked[cadence] = true
		}
	}
	for _, want := range []string{"monthly", "quarterly", "annual"} {
		if !checked[want] {
			t.Errorf("no GitHub template runs `sigcomply check --cadence %s`; this test checked nothing for it", want)
		}
	}
}

func checkCronsInsidePeriod(t *testing.T, path, body, cadence string) {
	t.Helper()
	cfg := &spec.PeriodConfig{} // the default calendar_quarter
	crons := cronLine.FindAllStringSubmatch(body, -1)
	if len(crons) == 0 {
		t.Errorf("%s: no cron schedule", path)
	}
	for _, c := range crons {
		fires := cronFirings(t, c[1], 2026, 2030)
		if len(fires) == 0 {
			t.Errorf("%s: cron %q never fires in 2026-2030", path, c[1])
		}
		for _, at := range fires {
			run, err := planner.DerivePeriod(cfg, at)
			if err != nil {
				t.Fatal(err)
			}
			folder, err := planner.CadencePeriod(cfg, at, cadence)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range []planner.Period{run, folder} {
				if at.Sub(p.Start) < 24*time.Hour {
					t.Errorf("%s: cron %q fires %s, within a day of the start of period %s", path, c[1], at.Format(time.RFC3339), p.ID)
				}
			}
		}
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
