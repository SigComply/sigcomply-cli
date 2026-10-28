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

	commands := map[string]bool{}
	for _, f := range files {
		body, err := os.ReadFile(f) //nolint:gosec // #nosec G304 -- written by init-ci in the test's own dir
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ciCommand.FindAllStringSubmatch(string(body), -1) {
			// `|| true` keeps an advisory step from failing the job; the
			// command itself must still succeed.
			commands[strings.TrimSpace(strings.TrimSuffix(m[1], "|| true"))] = true
		}
	}
	// One per cadence, on-push and the due-soon step. Fewer means the
	// regexp stopped matching the templates, not that they lost steps.
	if len(commands) < 7 {
		t.Fatalf("extracted %d distinct sigcomply commands from %d workflow files; want at least 7: %v", len(commands), len(files), commands)
	}
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
