package orchestrator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// hostileText is what an attacker who controls a resource name, an API
// error body or a rule's violation reason can put into `check` output.
const hostileText = "x\n::add-mask::secret\n::error::forged\x1b[2Khidden"

// assertSafeOutput checks that no printed line starts a GitHub Actions
// workflow command and no ANSI escape survives.
func assertSafeOutput(t *testing.T, out string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "::") || strings.HasPrefix(trimmed, "##[") {
			t.Errorf("output line starts a workflow command: %q", line)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("output carries an ANSI escape: %q", out)
	}
}

// TestRenderAndExitCode_SanitizesUntrustedText: every reason `check`
// prints for a failed or errored policy goes through log.Sanitize.
func TestRenderAndExitCode_SanitizesUntrustedText(t *testing.T) {
	var buf bytes.Buffer
	plan := &planner.RunPlan{Framework: testFramework, Period: planner.Period{ID: testPeriodID}}
	results := []core.PolicyResult{
		{PolicyID: "p1", Status: core.StatusFail, Violations: []core.Violation{{ResourceID: "r", Reason: hostileText}}},
		{PolicyID: "p2", Status: core.StatusError, Diag: map[string]any{"collect_error": hostileText}},
		{PolicyID: "p3", Status: core.StatusError, Diag: map[string]any{"rule_error": hostileText}},
	}
	renderAndExitCode(&buf, plan, results, spec.CIConfig{}, nil)
	assertSafeOutput(t, buf.String())
	if !strings.Contains(buf.String(), "forged") {
		t.Errorf("the reason text itself should still be shown: %q", buf.String())
	}
}
