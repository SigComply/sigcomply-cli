package cmd

import (
	"bytes"
	"context"
	"errors"
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
