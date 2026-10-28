package cmd

// Binary-level end-to-end tests. Everything else in this package calls
// command functions in-process; these build the real `sigcomply` binary
// once and run it as CI would: a fresh process, a minimal environment,
// and the exit code as the only verdict. They cover what an in-process
// test cannot see: main's os.Exit mapping, flag parsing through cobra,
// what lands on stdout/stderr, and what the process leaves in the vault.
//
// Most configs here are manual-evidence only. The one automated source
// that runs is GitHub, whose base_url lets the binary reach a local
// server replaying the committed cassette (e2e_github_test.go). Sources
// without an endpoint override (AWS, GCP, Azure) stay in-process
// (TestE2E_WalkingSkeleton in internal/orchestrator).
//
// Per-policy outcomes are pinned in testdata/e2e-outcomes/; regenerate
// with `go test ./cmd/sigcomply/ -run TestBinaryE2E -update` and read
// the diff (e2e_golden_test.go).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
)

// e2eCommitTime pins the commit time every binary run reports, so the
// audit period (2026-Q1 for quarterly entries) never depends on the
// wall clock.
var e2eCommitTime = time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)

const e2ePeriod = "2026-Q1"

const goosWindows = "windows"

// e2eBuild holds the binary built on first use. TestMain removes it.
var e2eBuild struct {
	once sync.Once
	dir  string
	path string
	err  error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if e2eBuild.dir != "" {
		_ = os.RemoveAll(e2eBuild.dir) //nolint:errcheck // best-effort temp cleanup
	}
	os.Exit(code)
}

// sigcomplyBinary builds the CLI from the module root once per test
// process, with the version the init-ci goldens are rendered with.
func sigcomplyBinary(t *testing.T) string {
	t.Helper()
	e2eBuild.once.Do(func() {
		dir, err := os.MkdirTemp("", "sigcomply-e2e-")
		if err != nil {
			e2eBuild.err = err
			return
		}
		e2eBuild.dir = dir
		name := "sigcomply"
		if runtime.GOOS == goosWindows {
			name += ".exe"
		}
		e2eBuild.path = filepath.Join(dir, name)
		ldflags := "-X main.version=" + goldenVersion + " -X main.commit=e2e"
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		build := exec.CommandContext(ctx, "go", "build", "-ldflags", ldflags, "-o", e2eBuild.path, "../..") //nolint:gosec // #nosec G204 -- fixed arguments; test-only build
		if out, err := build.CombinedOutput(); err != nil {
			e2eBuild.err = fmt.Errorf("go build: %w\n%s", err, out)
		}
	})
	if e2eBuild.err != nil {
		t.Fatalf("build sigcomply: %v", e2eBuild.err)
	}
	return e2eBuild.path
}

type e2eResult struct {
	code   int
	stdout string
	stderr string
}

// runSigcomply runs the binary in dir with a minimal environment: no
// inherited CI variables, no cloud credentials, the commit pinned. extra
// adds or overrides entries.
func runSigcomply(t *testing.T, dir string, extra []string, args ...string) e2eResult {
	t.Helper()
	bin := sigcomplyBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // #nosec G204 -- the binary this test built
	cmd.Dir = dir
	home := filepath.Join(dir, ".home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"AWS_CONFIG_FILE=" + os.DevNull,
		"AWS_SHARED_CREDENTIALS_FILE=" + os.DevNull,
		"CLOUDSDK_CONFIG=" + filepath.Join(home, "gcloud"),
		"AZURE_CONFIG_DIR=" + filepath.Join(home, "azure"),
		"GITHUB_SHA=0123456789abcdef0123456789abcdef01234567",
		"GITHUB_EVENT_HEAD_COMMIT_TIMESTAMP=" + e2eCommitTime.Format(time.RFC3339),
	}, extra...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return e2eResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func (r e2eResult) wantCode(t *testing.T, want int) {
	t.Helper()
	if r.code != want {
		t.Fatalf("exit code = %d; want %d\n--- stdout ---\n%s\n--- stderr ---\n%s", r.code, want, r.stdout, r.stderr)
	}
}

// wantNoUsage fails when a runtime error printed cobra's usage block,
// which buries the one-line error under the flag list (99fd507). Only
// --help prints usage.
func (r e2eResult) wantNoUsage(t *testing.T) {
	t.Helper()
	if strings.Contains(r.stdout, "Usage:") || strings.Contains(r.stderr, "Usage:") {
		t.Errorf("a runtime error printed the usage block\n--- stdout ---\n%s\n--- stderr ---\n%s", r.stdout, r.stderr)
	}
}

// e2eProject is a scratch project: a config, a local vault and a local
// manual-evidence store.
type e2eProject struct {
	dir, config, vault, manual string
}

func newE2EProject(t *testing.T) e2eProject {
	t.Helper()
	return newE2EProjectFor(t, defaultFW, "")
}

// newE2EProjectFor writes a project for framework with the manual source
// and, when extraSources is set, the YAML it holds appended under
// `sources:` (two-space indented entries).
func newE2EProjectFor(t *testing.T, framework, extraSources string) e2eProject {
	t.Helper()
	dir := t.TempDir()
	p := e2eProject{
		dir:    dir,
		config: filepath.Join(dir, ".sigcomply.yaml"),
		vault:  filepath.Join(dir, "vault"),
		manual: filepath.Join(dir, "evidence"),
	}
	if err := os.MkdirAll(p.manual, 0o750); err != nil {
		t.Fatal(err)
	}
	body := "schema_version: project.v1\n" +
		"framework: " + framework + "\n" +
		"vault:\n  backend: local\n  path: " + p.vault + "\n" +
		"sources:\n  manual.pdf:\n    backend: local\n    path: " + p.manual + "\n" +
		extraSources
	if err := os.WriteFile(p.config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// seedAllManualEvidence asks the binary which folders are empty
// (`evidence due --all -o json`) and drops a valid PDF in each, dated
// inside the period, so every manual policy passes. It returns the
// files it wrote.
func seedAllManualEvidence(t *testing.T, p e2eProject) []string {
	t.Helper()
	res := runSigcomply(t, p.dir, nil, "evidence", "due", "--all", "-o", "json")
	res.wantCode(t, 0)
	var due struct {
		PeriodID string `json:"period_id"`
		Missing  []struct {
			CatalogID string `json:"catalog_id"`
			FolderURI string `json:"folder_uri"`
		} `json:"missing"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &due); err != nil {
		t.Fatalf("evidence due JSON: %v\n%s", err, res.stdout)
	}
	if due.PeriodID != e2ePeriod {
		t.Errorf("evidence due period_id = %q; want %q", due.PeriodID, e2ePeriod)
	}
	if len(due.Missing) == 0 {
		t.Fatal("evidence due reported no empty folders for an empty store")
	}
	pdf, err := os.ReadFile(filepath.Join("..", "..", "internal", "sources", "manual", "testdata", "store", "manual", "e2e_doc_single", "2026-Q1", "policy.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	uploaded := e2eCommitTime.Add(-time.Hour)
	files := make([]string, 0, len(due.Missing))
	for _, m := range due.Missing {
		folder := strings.TrimPrefix(m.FolderURI, "file://")
		if !strings.HasPrefix(folder, p.manual) {
			t.Fatalf("%s: folder %q is outside the manual store %q", m.CatalogID, folder, p.manual)
		}
		if err := os.MkdirAll(folder, 0o750); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(folder, "evidence.pdf")
		if err := os.WriteFile(file, pdf, 0o600); err != nil { //nolint:gosec // #nosec G703 -- folder checked to be inside the test's own store above
			t.Fatal(err)
		}
		if err := os.Chtimes(file, uploaded, uploaded); err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	return files
}

func TestBinaryE2E_Check_AllEvidencePresentExits0(t *testing.T) {
	p := newE2EProject(t)
	seeded := seedAllManualEvidence(t, p)

	res := runSigcomply(t, p.dir, nil, "check", "--no-cloud")
	res.wantCode(t, 0)
	if !strings.Contains(res.stdout, "SigComply check soc2/"+e2ePeriod) {
		t.Errorf("stdout missing run header for %s:\n%s", e2ePeriod, res.stdout)
	}
	if strings.Contains(res.stderr, "Error:") {
		t.Errorf("stderr has an error on a passing run:\n%s", res.stderr)
	}

	runDir := singleRunDir(t, p.vault, "soc2")
	passed := 0
	for _, st := range readResultStatuses(t, runDir) {
		if st == core.StatusPass {
			passed++
		}
	}
	if passed != len(seeded) {
		t.Errorf("passing policies = %d; want one per seeded folder (%d)", passed, len(seeded))
	}
	// Every policy's exact outcome, not "pass or skip": an automated
	// policy that started passing with no source, or a manual one that
	// skipped, would otherwise go unnoticed.
	assertOutcomesGolden(t, runDir, "soc2_manual_seeded")
	assertVaultSigned(t, runDir)

	// Every folder is filled now, so nothing is due.
	due := runSigcomply(t, p.dir, nil, "evidence", "due", "--all", "-o", "json")
	due.wantCode(t, 0)
	var after struct {
		Missing []json.RawMessage `json:"missing"`
	}
	if err := json.Unmarshal([]byte(due.stdout), &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Missing) != 0 {
		t.Errorf("evidence due after seeding still lists missing entries:\n%s", due.stdout)
	}
}

func TestBinaryE2E_Check_MissingEvidenceExits1(t *testing.T) {
	p := newE2EProject(t)
	res := runSigcomply(t, p.dir, nil, "check", "--no-cloud")
	res.wantCode(t, 1)
	if strings.Contains(res.stderr, "Error:") {
		t.Errorf("a policy failure must not print an error:\n%s", res.stderr)
	}
	runDir := singleRunDir(t, p.vault, "soc2")
	failed := 0
	for _, st := range readResultStatuses(t, runDir) {
		if st == core.StatusFail {
			failed++
		}
	}
	if failed == 0 {
		t.Error("no failing policy recorded in the vault for a run that exited 1")
	}
	// A failing run is still a complete, signed audit record.
	assertVaultSigned(t, runDir)
}

func TestBinaryE2E_Check_ConfigErrorsExit3(t *testing.T) {
	cases := map[string]func(t *testing.T, p e2eProject){
		"missing config": func(t *testing.T, p e2eProject) {
			if err := os.Remove(p.config); err != nil {
				t.Fatal(err)
			}
		},
		"malformed yaml": func(t *testing.T, p e2eProject) {
			if err := os.WriteFile(p.config, []byte("framework: [soc2\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unknown source": func(t *testing.T, p e2eProject) {
			f, err := os.OpenFile(p.config, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }() //nolint:errcheck // test cleanup
			if _, err := f.WriteString("  made.up.source: {}\n"); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := newE2EProject(t)
			mutate(t, p)
			res := runSigcomply(t, p.dir, nil, "check", "--no-cloud")
			res.wantCode(t, 3)
			if !strings.Contains(res.stderr, "Error:") {
				t.Errorf("config error printed no message:\n%s", res.stderr)
			}
			res.wantNoUsage(t)
			if _, err := os.Stat(p.vault); err == nil {
				t.Errorf("a config error must stop before writing the vault")
			}
		})
	}
}

func TestBinaryE2E_Check_UnwritableVaultExits2(t *testing.T) {
	if runtime.GOOS == goosWindows {
		t.Skip("permission bits do not make a directory read-only on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	p := newE2EProject(t)
	if err := os.MkdirAll(p.vault, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.vault, 0o500); err != nil { //nolint:gosec // #nosec G302 -- read-only on purpose
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p.vault, 0o700) }) //nolint:errcheck,gosec // let TempDir cleanup remove it

	res := runSigcomply(t, p.dir, nil, "check", "--no-cloud")
	res.wantCode(t, 2)
	if !strings.Contains(res.stderr, "Error: vault:") {
		t.Errorf("stderr does not name the vault failure:\n%s", res.stderr)
	}
	res.wantNoUsage(t)
}

// fakeCloud stands in for both GitHub's OIDC token endpoint and the
// SigComply Cloud API, recording what the CLI sent.
type fakeCloud struct {
	srv        *httptest.Server
	runsStatus int

	mu          sync.Mutex
	audience    string
	tokenAuth   string
	runsAuth    string
	runsOIDC    string
	runsVersion string
	runsBody    []byte
	runsCalls   int
}

const (
	fakeRunnerBearer = "runner-request-token"
	fakeOIDCToken    = "header.payload.signature"
)

func newFakeCloud(t *testing.T, runsStatus int) *fakeCloud {
	t.Helper()
	fc := &fakeCloud{runsStatus: runsStatus}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oidc/token", func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		fc.audience = r.URL.Query().Get("audience")
		fc.tokenAuth = r.Header.Get("Authorization")
		fc.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"value":%q}`, fakeOIDCToken) //nolint:errcheck // test server
	})
	mux.HandleFunc("POST "+submitter.Path, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test server
		fc.mu.Lock()
		fc.runsCalls++
		fc.runsBody = body
		fc.runsAuth = r.Header.Get("Authorization")
		fc.runsOIDC = r.Header.Get("X-OIDC-Provider")
		fc.runsVersion = r.Header.Get("X-Sigcomply-CLI-Version")
		fc.mu.Unlock()
		w.WriteHeader(fc.runsStatus)
		_, _ = io.WriteString(w, `{"status":"ok"}`) //nolint:errcheck // test server
	})
	fc.srv = httptest.NewServer(mux)
	t.Cleanup(fc.srv.Close)
	return fc
}

// githubActionsEnv is what a GitHub Actions job with `id-token: write`
// exposes to the CLI. The request URL already carries a query string,
// as the real one does, so the CLI must append the audience with "&".
func (fc *fakeCloud) githubActionsEnv() []string {
	return []string{
		"CI=true",
		"GITHUB_ACTIONS=true",
		"GITHUB_REPOSITORY=acme/infra",
		"GITHUB_WORKFLOW=compliance",
		"GITHUB_RUN_ID=42",
		"GITHUB_REF_NAME=main",
		"ACTIONS_ID_TOKEN_REQUEST_URL=" + fc.srv.URL + "/oidc/token?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN=" + fakeRunnerBearer,
	}
}

func TestBinaryE2E_Check_SubmitsCountsWithOIDC(t *testing.T) {
	p := newE2EProject(t)
	fc := newFakeCloud(t, http.StatusCreated)

	res := runSigcomply(t, p.dir, fc.githubActionsEnv(), "check", "--cloud-url", fc.srv.URL)
	res.wantCode(t, 1) // no evidence uploaded: policy failures, not a submission problem
	if !strings.Contains(res.stderr, "submission accepted (HTTP 201)") {
		t.Errorf("stderr missing the submission confirmation:\n%s", res.stderr)
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.runsCalls != 1 {
		t.Fatalf("POST %s calls = %d; want 1", submitter.Path, fc.runsCalls)
	}
	if fc.audience != submitter.DefaultAudience {
		t.Errorf("OIDC audience requested = %q; want %q", fc.audience, submitter.DefaultAudience)
	}
	if fc.tokenAuth != "Bearer "+fakeRunnerBearer {
		t.Errorf("token request Authorization = %q", fc.tokenAuth)
	}
	if fc.runsAuth != "Bearer "+fakeOIDCToken {
		t.Errorf("runs Authorization = %q; want the minted OIDC token", fc.runsAuth)
	}
	if fc.runsOIDC != "github" {
		t.Errorf("X-OIDC-Provider = %q; want github", fc.runsOIDC)
	}
	if fc.runsVersion != goldenVersion {
		t.Errorf("X-Sigcomply-CLI-Version = %q; want %q", fc.runsVersion, goldenVersion)
	}
	assertPayloadMatchesGoldenShape(t, fc.runsBody)
}

// A rejected or failed submission is a warning: the run's exit code is
// the policy verdict, never the cloud's answer.
func TestBinaryE2E_Check_SubmissionFailureKeepsExitCode(t *testing.T) {
	for _, status := range []int{http.StatusUnprocessableEntity, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			p := newE2EProject(t)
			fc := newFakeCloud(t, status)
			res := runSigcomply(t, p.dir, fc.githubActionsEnv(), "check", "--cloud-url", fc.srv.URL)
			res.wantCode(t, 1)
			want := fmt.Sprintf("[warn] submit: submitter: %s%s returned %d", fc.srv.URL, submitter.Path, status)
			if !strings.Contains(res.stderr, want) {
				t.Errorf("stderr missing %q:\n%s", want, res.stderr)
			}
			if strings.Contains(res.stderr, "submission accepted") {
				t.Errorf("a %d was reported as accepted:\n%s", status, res.stderr)
			}
		})
	}
}

func TestBinaryE2E_Check_NoSubmissionOutsideCI(t *testing.T) {
	p := newE2EProject(t)
	fc := newFakeCloud(t, http.StatusCreated)
	res := runSigcomply(t, p.dir, nil, "check", "--cloud-url", fc.srv.URL)
	res.wantCode(t, 1)
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.runsCalls != 0 {
		t.Errorf("submitted %d time(s) outside CI; want none", fc.runsCalls)
	}
}

// --no-cloud wins over everything that would otherwise submit: CI, a
// mintable OIDC token and a cloud URL. The fake records zero requests to
// either endpoint.
func TestBinaryE2E_Check_NoCloudFlagSkipsSubmissionInCI(t *testing.T) {
	p := newE2EProject(t)
	fc := newFakeCloud(t, http.StatusCreated)
	res := runSigcomply(t, p.dir, fc.githubActionsEnv(), "check", "--no-cloud", "--cloud-url", fc.srv.URL)
	res.wantCode(t, 1)
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.runsCalls != 0 || fc.tokenAuth != "" {
		t.Errorf("--no-cloud run made %d submission(s) and token request auth %q; want none", fc.runsCalls, fc.tokenAuth)
	}
}

// A usage error (unknown flag) exits 2, not 1, so CI never reads it as
// a violation, and names the flag in one line.
func TestBinaryE2E_UnknownFlagExits2(t *testing.T) {
	res := runSigcomply(t, t.TempDir(), nil, "check", "--no-such-flag")
	res.wantCode(t, 2)
	if !strings.Contains(res.stderr, "Error: unknown flag: --no-such-flag") {
		t.Errorf("stderr does not name the unknown flag:\n%s", res.stderr)
	}
	res.wantNoUsage(t)
}

// --within-days: 0 lists only what closes in under a day, a negative
// value lists every empty folder (the same set as --all). At the pinned
// commit time (mid-February) no manual folder closes within a day.
func TestBinaryE2E_EvidenceDue_WithinDays(t *testing.T) {
	p := newE2EProject(t)
	due := func(args ...string) (missing []string, suppressed int) {
		t.Helper()
		res := runSigcomply(t, p.dir, nil, append([]string{"evidence", "due", "-o", "json"}, args...)...)
		res.wantCode(t, 0)
		var rep struct {
			Suppressed int `json:"suppressed"`
			Missing    []struct {
				CatalogID string `json:"catalog_id"`
			} `json:"missing"`
		}
		if err := json.Unmarshal([]byte(res.stdout), &rep); err != nil {
			t.Fatalf("evidence due %v JSON: %v\n%s", args, err, res.stdout)
		}
		for _, m := range rep.Missing {
			missing = append(missing, m.CatalogID)
		}
		sort.Strings(missing)
		return missing, rep.Suppressed
	}
	all, _ := due("--all")
	if len(all) == 0 {
		t.Fatal("--all lists nothing for an empty store")
	}
	if got, suppressed := due("--within-days", "0"); len(got) != 0 || suppressed != len(all) {
		t.Errorf("--within-days 0: missing %v, suppressed %d; want none missing and %d suppressed", got, suppressed, len(all))
	}
	if got, suppressed := due("--within-days", "-1"); strings.Join(got, ",") != strings.Join(all, ",") || suppressed != 0 {
		t.Errorf("--within-days -1: missing %d entries, suppressed %d; want the --all list (%d) and 0 suppressed", len(got), suppressed, len(all))
	}
}

func TestBinaryE2E_EvidenceCatalogJSON(t *testing.T) {
	dir := t.TempDir()
	for _, fw := range []string{defaultFW, isoFW} {
		res := runSigcomply(t, dir, nil, "evidence", "catalog", "-f", fw, "-o", "json")
		res.wantCode(t, 0)
		var cat manualcatalog.Catalog
		dec := json.NewDecoder(strings.NewReader(res.stdout))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cat); err != nil {
			t.Fatalf("%s: catalog JSON: %v", fw, err)
		}
		if cat.Framework != fw || len(cat.Entries) == 0 {
			t.Errorf("%s: framework=%q entries=%d", fw, cat.Framework, len(cat.Entries))
		}
		// The golden the Evidence SPA validates is what the binary prints.
		golden, err := os.ReadFile(filepath.Join("..", "..", "internal", "manualcatalog", "testdata", fw+"_golden.json")) //nolint:gosec // #nosec G304 -- fixed testdata path
		if err != nil {
			t.Fatal(err)
		}
		if res.stdout != string(golden) {
			t.Errorf("%s: evidence catalog -o json differs from internal/manualcatalog/testdata/%s_golden.json", fw, fw)
		}
	}
	res := runSigcomply(t, dir, nil, "evidence", "catalog", "-f", "hipaa", "-o", "json")
	res.wantCode(t, 3)
}

func TestBinaryE2E_EvidenceDue_ConfigErrorExits3(t *testing.T) {
	res := runSigcomply(t, t.TempDir(), nil, "evidence", "due")
	res.wantCode(t, 3)
}

func TestBinaryE2E_InitCI(t *testing.T) {
	cases := []struct {
		ci    string
		files map[string]string // written path -> golden in testdata/
	}{
		{ciGitHub, map[string]string{
			".github/workflows/compliance-daily.yml":   "golden_compliance-daily.yml",
			".github/workflows/compliance-on-push.yml": "golden_compliance-on-push.yml",
		}},
		{ciGitLab, map[string]string{".gitlab-ci.yml": "golden_gitlab-ci.yml"}},
	}
	for _, tc := range cases {
		t.Run(tc.ci, func(t *testing.T) {
			dir := t.TempDir()
			res := runSigcomply(t, dir, nil, "init-ci", "--ci", tc.ci)
			res.wantCode(t, 0)
			for written, golden := range tc.files {
				got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(written)))
				if err != nil {
					t.Fatalf("init-ci did not write %s: %v", written, err)
				}
				want, err := os.ReadFile(filepath.Join("testdata", golden))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s differs from testdata/%s", written, golden)
				}
				if !strings.Contains(res.stdout, written) {
					t.Errorf("stdout does not list %s:\n%s", written, res.stdout)
				}
			}
			// A second run refuses to overwrite: a config error.
			again := runSigcomply(t, dir, nil, "init-ci", "--ci", tc.ci)
			again.wantCode(t, 3)
		})
	}
	res := runSigcomply(t, t.TempDir(), nil, "init-ci")
	res.wantCode(t, 3)
}

// singleRunDir returns the only run folder under {framework}/{e2ePeriod}.
func singleRunDir(t *testing.T, vault, framework string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(vault, framework, e2ePeriod, "run_*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("run folders under %s/%s = %v; want exactly one", framework, e2ePeriod, matches)
	}
	return matches[0]
}

func readResultStatuses(t *testing.T, runDir string) map[string]core.PolicyStatus {
	t.Helper()
	results := readResults(t, runDir)
	out := make(map[string]core.PolicyStatus, len(results))
	for id := range results {
		out[id] = results[id].Status
	}
	return out
}

// assertVaultSigned checks what the binary wrote is a verifiable audit
// record: the run manifest verifies, lists every other file in the run
// folder with its exact hash, and every envelope's signature verifies.
func assertVaultSigned(t *testing.T, runDir string) {
	t.Helper()
	var manifest core.Manifest
	readJSON(t, filepath.Join(runDir, "manifest.json"), &manifest)
	if err := sign.VerifyManifest(&manifest); err != nil {
		t.Fatalf("manifest does not verify: %v", err)
	}

	var onDisk []string
	envelopes := 0
	err := filepath.WalkDir(runDir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return werr
		}
		rel, err := filepath.Rel(runDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" {
			return nil
		}
		onDisk = append(onDisk, rel)
		data, err := os.ReadFile(path) //nolint:gosec // #nosec G304 -- walking the test's own vault
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if got, want := manifest.FileHashes[rel], "sha256:"+hex.EncodeToString(sum[:]); got != want {
			t.Errorf("manifest hash for %s = %q; file hashes to %q", rel, got, want)
		}
		if strings.Contains(rel, "/envelopes/") {
			envelopes++
			var env core.Envelope
			if err := json.Unmarshal(data, &env); err != nil {
				t.Errorf("%s: %v", rel, err)
			} else if err := sign.VerifyEnvelope(&env); err != nil {
				t.Errorf("envelope %s does not verify: %v", rel, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != len(manifest.FileHashes) {
		listed := make([]string, 0, len(manifest.FileHashes))
		for k := range manifest.FileHashes {
			listed = append(listed, k)
		}
		sort.Strings(listed)
		sort.Strings(onDisk)
		t.Errorf("manifest lists %d files, run folder holds %d\nlisted: %v\non disk: %v", len(listed), len(onDisk), listed, onDisk)
	}
	if envelopes == 0 {
		t.Error("run folder holds no signed envelopes")
	}
}

// assertPayloadMatchesGoldenShape compares the POSTed body's keys with
// the golden wire contract (internal/aggregator/testdata/cloud_golden.json),
// which Rails consumes byte-for-byte. Every object must have exactly the
// golden's keys, except that a policy may omit keys the golden shows as
// optional (absent from at least one golden policy).
func assertPayloadMatchesGoldenShape(t *testing.T, body []byte) {
	t.Helper()
	var golden, got map[string]any
	readJSON(t, filepath.Join("..", "..", "internal", "aggregator", "testdata", "cloud_golden.json"), &golden)
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("POST body is not JSON: %v\n%s", err, body)
	}
	assertSameKeys(t, "payload", golden, got)
	gs, _ := golden["summary"].(map[string]any)      //nolint:errcheck // nil map fails the comparison
	gotSummary, _ := got["summary"].(map[string]any) //nolint:errcheck // same
	assertSameKeys(t, "summary", gs, gotSummary)
	// repository and environment fields are omitempty: the CLI sends what
	// the CI exposes (worker_image is never detected today), so each sent
	// key must be in the golden, and provider is always present.
	for _, obj := range []string{"repository", "environment"} {
		g, _ := golden[obj].(map[string]any) //nolint:errcheck // nil map fails below
		o, _ := got[obj].(map[string]any)    //nolint:errcheck // same
		for k := range o {
			if _, ok := g[k]; !ok {
				t.Errorf("%s has key %q the golden contract does not", obj, k)
			}
		}
		if _, ok := o["provider"]; !ok {
			t.Errorf("%s lacks provider", obj)
		}
	}
	if got["schema"] != golden["schema"] {
		t.Errorf("schema = %v; golden has %v", got["schema"], golden["schema"])
	}

	goldenPolicies, _ := golden["policies"].([]any) //nolint:errcheck // checked in assertPolicyKeys
	gotPolicies, _ := got["policies"].([]any)       //nolint:errcheck // same
	assertPolicyKeys(t, goldenPolicies, gotPolicies)
}

// assertPolicyKeys: a sent policy may only carry keys some golden policy
// has, and must carry every key all golden policies have.
func assertPolicyKeys(t *testing.T, goldenPolicies, gotPolicies []any) {
	t.Helper()
	if len(goldenPolicies) == 0 || len(gotPolicies) == 0 {
		t.Fatalf("policies: golden %d, sent %d; want both non-empty", len(goldenPolicies), len(gotPolicies))
	}
	allowed, seen := map[string]bool{}, map[string]int{}
	for _, raw := range goldenPolicies {
		gp, ok := raw.(map[string]any)
		if !ok {
			t.Fatal("golden policy is not an object")
		}
		for k := range gp {
			allowed[k] = true
			seen[k]++
		}
	}
	for i, raw := range gotPolicies {
		pol, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("policies[%d] is not an object", i)
		}
		for k := range pol {
			if !allowed[k] {
				t.Errorf("policies[%d] has key %q the golden contract does not", i, k)
			}
		}
		for k, n := range seen {
			if _, present := pol[k]; n == len(goldenPolicies) && !present {
				t.Errorf("policies[%d] lacks key %q every golden policy has", i, k)
			}
		}
	}
}

func assertSameKeys(t *testing.T, what string, want, got map[string]any) {
	t.Helper()
	keys := func(m map[string]any) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if w, g := strings.Join(keys(want), ","), strings.Join(keys(got), ","); w != g {
		t.Errorf("%s keys = [%s]; golden has [%s]", what, g, w)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}
