package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNewRootCmd_RegistersSubcommands(t *testing.T) {
	root := newRootCmd()
	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"check", "version", "init-ci", "build", "report"} {
		if !names[want] {
			t.Errorf("subcommand %q not registered", want)
		}
	}
}

func TestVersionCmd_PrintsVersionInfo(t *testing.T) {
	SetVersionInfo("1.2.3", "abc123", "2026-01-01T00:00:00Z")
	defer SetVersionInfo("dev", "unknown", "unknown")
	cmd := newVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := out.String()
	for _, want := range []string{"1.2.3", "abc123"} {
		if !strings.Contains(got, want) {
			t.Errorf("version output missing %q: %q", want, got)
		}
	}
}

func TestExitCodeError_Unwrap(t *testing.T) {
	inner := errors.New("boom")
	e := &exitCodeError{code: 3, err: inner}
	if !errors.Is(e, inner) {
		t.Errorf("errors.Is should match inner")
	}
	if e.Error() != "boom" {
		t.Errorf("Error() = %q; want %q", e.Error(), "boom")
	}
	bare := &exitCodeError{code: 2}
	if !strings.Contains(bare.Error(), "exit 2") {
		t.Errorf("bare Error() = %q", bare.Error())
	}
}

func TestDetectBranch_PrefersGitHubRefName(t *testing.T) {
	t.Setenv("GITHUB_REF_NAME", "feature/x")
	t.Setenv("CI_COMMIT_REF_NAME", "ignored")
	if got := detectBranch(); got != "feature/x" {
		t.Errorf("detectBranch = %q", got)
	}
}

func TestDetectBranch_GitLabFallback(t *testing.T) {
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("CI_COMMIT_REF_NAME", "main")
	if got := detectBranch(); got != "main" {
		t.Errorf("detectBranch = %q", got)
	}
}

func TestDetectBranch_EmptyWhenNoEnv(t *testing.T) {
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("CI_COMMIT_REF_NAME", "")
	t.Setenv("GIT_BRANCH", "")
	if got := detectBranch(); got != "" {
		t.Errorf("detectBranch = %q; want empty", got)
	}
}

// A command may wrap an exitCodeError (fmt.Errorf("...: %w", ec)). The
// stamped exit code must survive the wrapping; only an unstamped error
// falls back to 2.
func TestExitCodeFor_WrappedExitErrorKeepsCode(t *testing.T) {
	wrapped := fmt.Errorf("context: %w", &exitCodeError{code: 3, err: errors.New("bad config")})
	var stderr bytes.Buffer
	if got := exitCodeFor(wrapped, &stderr); got != 3 {
		t.Errorf("exitCodeFor(wrapped code 3) = %d; want 3", got)
	}
	if !strings.Contains(stderr.String(), "bad config") {
		t.Errorf("stderr = %q; want the wrapped message", stderr.String())
	}

	stderr.Reset()
	bare := fmt.Errorf("outer: %w", &exitCodeError{code: 1})
	if got := exitCodeFor(bare, &stderr); got != 1 {
		t.Errorf("exitCodeFor(wrapped bare code 1) = %d; want 1", got)
	}

	stderr.Reset()
	if got := exitCodeFor(errors.New("plain"), &stderr); got != 2 {
		t.Errorf("exitCodeFor(plain) = %d; want 2", got)
	}
	if got := exitCodeFor(nil, &stderr); got != 0 {
		t.Errorf("exitCodeFor(nil) = %d; want 0", got)
	}
}

// The final error line reaches the CI log: text an error carries from a
// source, the vault or SigComply Cloud must not inject lines, workflow
// commands or terminal escapes there.
func TestExitCodeFor_SanitizesTheErrorLine(t *testing.T) {
	var stderr bytes.Buffer
	exitCodeFor(errors.New("vault: read x\n::add-mask::y\x1b[31m"), &stderr)
	out := strings.TrimSuffix(stderr.String(), "\n")
	for _, bad := range []string{"\n", "::add-mask::", "\x1b"} {
		if strings.Contains(out, bad) {
			t.Errorf("error line carries %q: %q", bad, out)
		}
	}
	if !strings.Contains(out, "vault: read x") {
		t.Errorf("error line lost its message: %q", out)
	}
}
