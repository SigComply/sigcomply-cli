package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/sigcomply/sigcomply-cli/internal/storagetest"
)

// ciCommand matches a `sigcomply …` step in a generated workflow: a
// GitHub `run: sigcomply …` or a GitLab script item `- sigcomply …`. The
// capture stops before a trailing `|| …`, which only decides how the job
// treats the command's exit code; the command itself must still succeed.
var ciCommand = regexp.MustCompile(`(?m)^\s*(?:run:|-)\s+sigcomply\s+(.+?)(?:\s+\|\|.*)?\s*$`)

// TestBinaryE2E_InitCI_GeneratedCommandsRun runs every `sigcomply`
// command line the init-ci workflows contain against a seeded project, so
// a template that passes a flag the CLI no longer accepts, or a command
// that errors, fails here rather than in a customer's first scheduled run.
func TestBinaryE2E_InitCI_GeneratedCommandsRun(t *testing.T) {
	p := newE2EProject(t)
	seedAllManualEvidence(t, p)
	for _, ci := range []string{ciGitHub, ciGitLab} {
		runSigcomply(t, p.dir, nil, "init-ci", "--ci", ci).wantCode(t, 0)
	}
	files, err := filepath.Glob(filepath.Join(p.dir, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join(p.dir, ".gitlab-ci.yml"))

	// The fewest `sigcomply` lines each generated file holds: GitLab has
	// the --pr job, the --scheduled job and the due-soon step; the GitHub
	// scheduled workflow has its check and the due-soon step; the on-push
	// workflow has one check. Fewer means the regexp stopped matching
	// that file, not that it lost steps, so each file is counted alone.
	minPerFile := map[string]int{".gitlab-ci.yml": 3, scheduledWorkflow: 2}
	commands := map[string]bool{}
	for _, f := range files {
		body, err := os.ReadFile(f) //nolint:gosec // #nosec G304 -- written by init-ci in the test's own dir
		if err != nil {
			t.Fatal(err)
		}
		found := ciCommand.FindAllStringSubmatch(string(body), -1)
		want, ok := minPerFile[filepath.Base(f)]
		if !ok {
			want = 1
		}
		if len(found) < want {
			t.Errorf("%s: extracted %d sigcomply commands; want at least %d", filepath.Base(f), len(found), want)
		}
		for _, m := range found {
			commands[m[1]] = true
		}
	}
	if len(files) != 3 {
		t.Fatalf("init-ci wrote %d workflow files; want the two GitHub workflows and .gitlab-ci.yml", len(files))
	}
	assertScaffoldedCommands(t, commands)
	sorted := make([]string, 0, len(commands))
	for c := range commands {
		sorted = append(sorted, c)
	}
	sort.Strings(sorted)
	for _, c := range sorted {
		t.Run(c, func(t *testing.T) {
			res := runSigcomply(t, p.dir, nil, strings.Fields(c)...)
			// Every manual folder is filled, so nothing may fail; 2 or 3
			// would mean the scaffolded command itself is broken.
			res.wantCode(t, 0)
		})
	}
}

// The scaffolded `check` lines, and the predicate for them: the full
// scheduled run, which submits, or the --pr run, which never does.
const (
	scaffoldedScheduledCheck = "check --scheduled"
	scaffoldedPRCheck        = "check --pr"
)

func isScaffoldedCheck(c string) bool {
	return !strings.HasPrefix(c, "check") || c == scaffoldedScheduledCheck || c == scaffoldedPRCheck
}

// assertScaffoldedCommands checks the init-ci workflows run exactly the
// scheduled check, the --pr check and the due-soon step.
func assertScaffoldedCommands(t *testing.T, commands map[string]bool) {
	t.Helper()
	for c := range commands {
		if !isScaffoldedCheck(c) {
			t.Errorf("scaffolded %q; want only `%s` and `%s`", c, scaffoldedScheduledCheck, scaffoldedPRCheck)
		}
	}
	for _, want := range []string{scaffoldedScheduledCheck, scaffoldedPRCheck, "evidence due --within-days 30"} {
		if !commands[want] {
			t.Errorf("no workflow runs `sigcomply %s`", want)
		}
	}
}

// summaryLine matches the counts line `check` prints after its header.
var summaryLine = regexp.MustCompile(`pass=(\d+) fail=(\d+) carried=(\d+) skip=(\d+) error=(\d+)`)

type runCounts struct{ pass, fail, carried, skip, errored int }

func parseRunCounts(t *testing.T, stdout string) runCounts {
	t.Helper()
	m := summaryLine.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("no summary line in stdout:\n%s", stdout)
	}
	n := make([]int, 5)
	for i := range n {
		v, err := strconv.Atoi(m[i+1])
		if err != nil {
			t.Fatal(err)
		}
		n[i] = v
	}
	return runCounts{pass: n[0], fail: n[1], carried: n[2], skip: n[3], errored: n[4]}
}

// TestBinaryE2E_Check_ScheduledCarriesStateThroughVault: a scheduled run
// records per-policy state in the vault, and the next scheduled run reads
// it and carries the passes forward instead of re-evaluating. Deleting the
// state makes the next run a first run again, which proves the vault
// state, not the process, carried them. The coverage view must read a
// carried-forward manual pass as a document on file, as it read the
// first run's pass.
func TestBinaryE2E_Check_ScheduledCarriesStateThroughVault(t *testing.T) {
	p := newE2EProject(t)
	seeded := len(seedAllManualEvidence(t, p))
	scheduled := func() runCounts {
		t.Helper()
		res := runSigcomply(t, p.dir, nil, "check", "--scheduled", "--no-cloud")
		res.wantCode(t, 0)
		return parseRunCounts(t, res.stdout)
	}

	if c := scheduled(); c.pass != seeded || c.carried != 0 {
		t.Fatalf("first scheduled run: %+v; want %d passes and nothing carried", c, seeded)
	}
	stateDir := filepath.Join(p.vault, "state", defaultFW, "policies")
	shards, err := filepath.Glob(filepath.Join(stateDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(shards) < seeded {
		t.Fatalf("state shards under %s = %d; want at least one per evaluated policy (%d)", stateDir, len(shards), seeded)
	}

	afterFirst := manualCoverageLine(t, p)
	if !strings.HasSuffix(afterFirst, ", 0 without") {
		t.Errorf("coverage after the first scheduled run: %q; want every manual control on file", afterFirst)
	}

	if c := scheduled(); c.carried != seeded || c.pass != 0 {
		t.Errorf("second scheduled run: %+v; want all %d passes carried forward", c, seeded)
	}
	if got := manualCoverageLine(t, p); got != afterFirst {
		t.Errorf("coverage after the carry-forward run: %q; want %q (nothing left the evidence store)", got, afterFirst)
	}

	if err := os.RemoveAll(filepath.Join(p.vault, "state")); err != nil {
		t.Fatal(err)
	}
	if c := scheduled(); c.pass != seeded || c.carried != 0 {
		t.Errorf("scheduled run after deleting state: %+v; want a first run again (%d passes)", c, seeded)
	}
}

// TestBinaryE2E_Check_ScheduledCarriesStateThroughS3Vault is the
// carry-forward test above with the vault and the manual evidence in S3
// (a loopback fake reached through `endpoint` and `force_path_style`), as
// a customer runs it. Every manual PDF is put into the bucket directly,
// so the first run's passes prove the binary listed and read them over
// the S3 API, and the second run's carried passes prove it read the state
// it wrote there.
func TestBinaryE2E_Check_ScheduledCarriesStateThroughS3Vault(t *testing.T) {
	const bucket = "acme-evidence"
	fake := storagetest.NewS3(t, bucket, 1000)
	dir := t.TempDir()
	cfg := "schema_version: project.v1\n" +
		"framework: " + defaultFW + "\n" +
		"period:\n  time_basis: commit\n" +
		"vault:\n  backend: s3\n  bucket: " + bucket + "\n  region: us-east-1\n  prefix: vault/\n" +
		"  endpoint: " + fake.URL() + "\n  force_path_style: true\n" +
		"sources:\n  manual.pdf:\n    backend: s3\n    bucket: " + bucket + "\n    region: us-east-1\n    prefix: manual/\n" +
		"    endpoint: " + fake.URL() + "\n    force_path_style: true\n"
	if err := os.WriteFile(filepath.Join(dir, ".sigcomply.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"AWS_ACCESS_KEY_ID=test-access-key", "AWS_SECRET_ACCESS_KEY=test-secret", "AWS_EC2_METADATA_DISABLED=true"}

	seeded := seedS3ManualEvidence(t, dir, env, fake, bucket)
	scheduled := func() runCounts {
		t.Helper()
		res := runSigcomply(t, dir, env, checkCmd, "--scheduled", "--no-cloud")
		res.wantCode(t, 0)
		return parseRunCounts(t, res.stdout)
	}
	if c := scheduled(); c.pass != seeded || c.carried != 0 {
		t.Fatalf("first scheduled run: %+v; want %d passes read from S3 and nothing carried", c, seeded)
	}
	shard := "vault/state/" + defaultFW + "/policies/"
	if n := countObjects(t, fake, bucket, shard); n < seeded {
		t.Fatalf("state shards under s3://%s/%s = %d; want at least one per evaluated policy (%d)", bucket, shard, n, seeded)
	}
	if c := scheduled(); c.carried != seeded || c.pass != 0 {
		t.Errorf("second scheduled run: %+v; want all %d passes carried forward from the S3 state", c, seeded)
	}
}

// seedS3ManualEvidence asks the binary which manual folders are empty and
// puts a valid PDF, dated inside the period, into each one in the fake
// bucket. It returns how many it put.
func seedS3ManualEvidence(t *testing.T, dir string, env []string, fake *storagetest.S3, bucket string) int {
	t.Helper()
	res := runSigcomply(t, dir, env, "evidence", "due", "--all", "-o", "json")
	res.wantCode(t, 0)
	var due struct {
		Missing []struct {
			CatalogID string `json:"catalog_id"`
			FolderURI string `json:"folder_uri"`
		} `json:"missing"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &due); err != nil {
		t.Fatalf("evidence due JSON: %v\n%s", err, res.stdout)
	}
	if len(due.Missing) == 0 {
		t.Fatal("evidence due reported no empty folders for an empty bucket")
	}
	pdf, err := os.ReadFile(filepath.Join("..", "..", "internal", "sources", "manual", "testdata", "store", "manual", "e2e_doc_single", "2026-Q1", "policy.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	uploaded := e2eCommitTime.Add(-time.Hour)
	for _, m := range due.Missing {
		key, ok := strings.CutPrefix(m.FolderURI, "s3://"+bucket+"/")
		if !ok || !strings.HasPrefix(key, "manual/") {
			t.Fatalf("%s: folder %q is not under s3://%s/manual/", m.CatalogID, m.FolderURI, bucket)
		}
		fake.Put(strings.TrimSuffix(key, "/")+"/evidence.pdf", pdf, uploaded)
	}
	return len(due.Missing)
}

// countObjects lists the fake bucket under prefix through the S3 API.
func countObjects(t *testing.T, fake *storagetest.S3, bucket, prefix string) int {
	t.Helper()
	pages := s3.NewListObjectsV2Paginator(fake.Client(), &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix)})
	n := 0
	for pages.HasMorePages() {
		page, err := pages.NextPage(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		n += len(page.Contents)
	}
	return n
}

// manualCoverageLine returns the manual-controls headline of
// `report --view coverage` for the E2E period.
func manualCoverageLine(t *testing.T, p e2eProject) string {
	t.Helper()
	res := runSigcomply(t, p.dir, nil, "report", "--period", e2ePeriod, "--view", "coverage")
	res.wantCode(t, 0)
	for _, line := range strings.Split(res.stdout, "\n") {
		if strings.Contains(line, "manual control(s) with evidence on file") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("no manual headline in coverage output:\n%s", res.stdout)
	return ""
}

// TestBinaryE2E_Check_PRMode: --pr evaluates on_push policies only. No
// manual policy is on_push, so an unseeded project that fails a full run
// passes a PR run.
func TestBinaryE2E_Check_PRMode(t *testing.T) {
	p := newE2EProject(t)
	runSigcomply(t, p.dir, nil, "check", "--no-cloud").wantCode(t, 1)
	res := runSigcomply(t, p.dir, nil, "check", "--pr", "--no-cloud")
	res.wantCode(t, 0)
	if c := parseRunCounts(t, res.stdout); c.fail != 0 || c.pass != 0 {
		t.Errorf("--pr on a manual-only project evaluated policies: %+v", c)
	}
}
