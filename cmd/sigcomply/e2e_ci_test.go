package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ciCommand matches a `sigcomply …` step in a generated workflow: a
// GitHub `run: sigcomply …` or a GitLab script item `- sigcomply …`.
var ciCommand = regexp.MustCompile(`(?m)^\s*(?:run:|-)\s+sigcomply\s+(.+?)\s*$`)

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
			// `|| true` keeps an advisory step from failing the job; the
			// command itself must still succeed.
			commands[strings.TrimSpace(strings.TrimSuffix(m[1], "|| true"))] = true
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
// state, not the process, carried them.
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

	if c := scheduled(); c.carried != seeded || c.pass != 0 {
		t.Errorf("second scheduled run: %+v; want all %d passes carried forward", c, seeded)
	}

	if err := os.RemoveAll(filepath.Join(p.vault, "state")); err != nil {
		t.Fatal(err)
	}
	if c := scheduled(); c.pass != seeded || c.carried != 0 {
		t.Errorf("scheduled run after deleting state: %+v; want a first run again (%d passes)", c, seeded)
	}
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
