package fixturehygiene

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// scriptPath resolves scripts/check-fixtures.sh relative to this test file so
// the test works regardless of the working directory `go test` chooses.
func scriptPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/fixturehygiene/ -> repo root -> scripts/check-fixtures.sh
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", "check-fixtures.sh")
}

// run executes the gate against dir and returns its exit code and combined output.
func run(t *testing.T, dir string) (exitCode int, output string) {
	t.Helper()
	// #nosec G204 -- drives a fixed in-repo script against a test temp dir.
	out, err := exec.CommandContext(t.Context(), "bash", scriptPath(t), dir).CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(out)
	}
	t.Fatalf("running gate: %v\n%s", err, out)
	return -1, ""
}

// writeFixture drops content into a fresh temp dir and returns it.
func writeFixture(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cassette.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGateFailsOnPlantedSecrets(t *testing.T) {
	cases := map[string]string{
		"aws access key": "key: AKIAIOSFODNN7REALKEY1\n",
		"aws account id": "account: \"123456789012\"\n",
		"real arn":       "arn: arn:aws:iam::123456789012:user/alice\n",
		"email address":  "owner: alice@acmecorp.com\n",
		"bearer token":   "Authorization: Bearer ghp_aBcD1234EfGh5678IjKl\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			code, out := run(t, writeFixture(t, content))
			if code == 0 {
				t.Fatalf("expected non-zero exit for planted %q, got 0\n%s", name, out)
			}
		})
	}
}

func TestGatePassesOnPlaceholders(t *testing.T) {
	// The §4 stable placeholders must never trip the gate.
	placeholders := "key: AKIAEXAMPLE0000000000\n" +
		"account: \"000000000000\"\n" +
		"arn: arn:aws:iam::000000000000:user/example-user\n" +
		"owner: user@example.com\n" +
		"Authorization: Bearer REDACTED\n"
	code, out := run(t, writeFixture(t, placeholders))
	if code != 0 {
		t.Fatalf("expected clean exit for placeholders, got %d\n%s", code, out)
	}
}

func TestGatePassesOnCleanTree(t *testing.T) {
	code, out := run(t, writeFixture(t, "status: passed\ncount: 3\n"))
	if code != 0 {
		t.Fatalf("expected clean exit, got %d\n%s", code, out)
	}
}

func TestGatePassesOnEmptyDir(t *testing.T) {
	code, out := run(t, t.TempDir())
	if code != 0 {
		t.Fatalf("expected clean exit on empty dir, got %d\n%s", code, out)
	}
}
