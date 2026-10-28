package scripts_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// publishFixture is a work clone with a bare origin, a fake gh on PATH
// that logs its arguments, and two commits: head (the one to release)
// and other (its parent).
type publishFixture struct {
	t           *testing.T
	work, gh    string
	ghLog       string
	head, other string
	env         []string
}

const fakeGH = `#!/bin/sh
echo "$*" >> "$FAKE_GH_LOG"
if [ "$1 $2" = "release view" ]; then
  [ -f "$FAKE_GH_ASSETS" ] || exit 1
  cat "$FAKE_GH_ASSETS"
fi
exit 0
`

func newPublishFixture(t *testing.T) *publishFixture {
	t.Helper()
	dir := t.TempDir()
	f := &publishFixture{t: t, work: filepath.Join(dir, "work"), ghLog: filepath.Join(dir, "gh.log")}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o755); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	f.gh = filepath.Join(dir, "assets.txt")
	f.env = append(envWithoutGitRepoVars(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"FAKE_GH_LOG="+f.ghLog, "FAKE_GH_ASSETS="+f.gh,
		"GITHUB_REPOSITORY=example/repo",
	)
	origin := filepath.Join(dir, "origin.git")
	f.git(dir, "init", "-q", "--bare", origin)
	f.git(dir, "init", "-q", f.work)
	f.git(f.work, "remote", "add", "origin", origin)
	f.git(f.work, "commit", "-q", "--allow-empty", "-m", "one")
	f.other = f.git(f.work, "rev-parse", "HEAD")
	f.git(f.work, "commit", "-q", "--allow-empty", "-m", "two")
	f.head = f.git(f.work, "rev-parse", "HEAD")
	f.git(f.work, "push", "-q", "origin", "HEAD:refs/heads/main")
	return f
}

// envWithoutGitRepoVars drops the variables git exports to hooks
// (GIT_DIR, GIT_INDEX_FILE, GIT_WORK_TREE, ...). Under a pre-commit hook in
// a linked worktree they name the outer repository's absolute paths, so
// the fixture's git commands would act on that repository, not on the
// temporary clone.
func envWithoutGitRepoVars() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR",
			"GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_PREFIX":
			continue
		}
		out = append(out, kv)
	}
	return out
}

func (f *publishFixture) git(dir string, args ...string) string {
	f.t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...) //nolint:gosec // test-controlled git arguments
	cmd.Dir = dir
	cmd.Env = f.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// publish runs the script for v1.2.3 with two assets, as of commit head.
func (f *publishFixture) publish() (string, error) {
	f.t.Helper()
	script, err := filepath.Abs("publish-release.sh")
	if err != nil {
		f.t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), "bash", script, "v1.2.3", "dist/a.tar.gz", "dist/checksums.txt") //nolint:gosec // fixed script and arguments
	cmd.Dir = f.work
	cmd.Env = append(append([]string{}, f.env...), "GITHUB_SHA="+f.head)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f *publishFixture) remoteTag() string {
	f.t.Helper()
	return f.git(f.work, "ls-remote", "origin", "refs/tags/v1.2.3^{}")
}

func (f *publishFixture) ghCalls() string {
	b, err := os.ReadFile(f.ghLog)
	if err != nil && !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
	return string(b)
}

// First run: pushes an annotated tag at GITHUB_SHA and creates the
// prerelease with every asset.
func TestPublishRelease_FirstRun(t *testing.T) {
	f := newPublishFixture(t)
	if out, err := f.publish(); err != nil {
		t.Fatalf("publish: %v\n%s", err, out)
	}
	if got := f.remoteTag(); !strings.HasPrefix(got, f.head) {
		t.Errorf("origin tag = %q; want it to peel to %s", got, f.head)
	}
	calls := f.ghCalls()
	if !strings.Contains(calls, "release create v1.2.3") || !strings.Contains(calls, "--prerelease") ||
		!strings.Contains(calls, "dist/a.tar.gz dist/checksums.txt") {
		t.Errorf("gh calls do not create the prerelease with its assets:\n%s", calls)
	}
}

// A re-run after the tag push and the release both succeeded, with one
// asset missing: no second push, no create, only the missing asset.
func TestPublishRelease_RerunIsIdempotent(t *testing.T) {
	f := newPublishFixture(t)
	if out, err := f.publish(); err != nil {
		t.Fatalf("first publish: %v\n%s", err, out)
	}
	if err := os.WriteFile(f.gh, []byte("a.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.ghLog); err != nil {
		t.Fatal(err)
	}
	out, err := f.publish()
	if err != nil {
		t.Fatalf("re-run failed: %v\n%s", err, out)
	}
	calls := f.ghCalls()
	if strings.Contains(calls, "release create") {
		t.Errorf("re-run created the release again:\n%s", calls)
	}
	if !strings.Contains(calls, "release upload v1.2.3 --repo example/repo dist/checksums.txt\n") {
		t.Errorf("re-run did not upload exactly the missing asset:\n%s", calls)
	}
}

// A tag already on origin at another commit is never moved, and nothing
// is published for it.
func TestPublishRelease_TagElsewhereFails(t *testing.T) {
	f := newPublishFixture(t)
	f.git(f.work, "tag", "-a", "v1.2.3", "-m", "stray", f.other)
	f.git(f.work, "push", "-q", "origin", "refs/tags/v1.2.3")
	out, err := f.publish()
	if err == nil {
		t.Fatalf("publish succeeded with the tag at another commit:\n%s", out)
	}
	if !strings.Contains(out, "already exists on origin at "+f.other) {
		t.Errorf("error does not name the stray tag's commit:\n%s", out)
	}
	if got := f.remoteTag(); !strings.HasPrefix(got, f.other) {
		t.Errorf("origin tag moved: %q", got)
	}
	if calls := f.ghCalls(); calls != "" {
		t.Errorf("gh was called although the tag is wrong:\n%s", calls)
	}
}
