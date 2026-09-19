package core_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// TestResultReason covers the projection of a PolicyResult onto the
// one-line explanation shown under a policy in `check` output and in the
// report's REASON column.
func TestResultReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result core.PolicyResult
		want   string
	}{
		{
			name:   "error prefers collect_error",
			result: core.PolicyResult{Status: core.StatusError, Diag: map[string]any{"collect_error": "aws.iam: access denied"}},
			want:   "aws.iam: access denied",
		},
		{
			name:   "error falls back to rule_error then reason",
			result: core.PolicyResult{Status: core.StatusError, Diag: map[string]any{"reason": "filter could not be evaluated"}},
			want:   "filter could not be evaluated",
		},
		{
			name:   "error with no diagnostic still explains itself",
			result: core.PolicyResult{Status: core.StatusError},
			want:   "evaluation error (see the run's result.json in the vault)",
		},
		{
			name:   "plain pass has nothing to say",
			result: core.PolicyResult{Status: core.StatusPass},
			want:   "",
		},
		{
			name:   "fail reports the first violation",
			result: core.PolicyResult{Status: core.StatusFail, ResourcesFailed: 1, ResourcesEvaluated: 3, Violations: []core.Violation{{Reason: testViolationBucketOpen}}},
			want:   testViolationBucketOpen,
		},
		{
			name:   "fail with several violations counts them",
			result: core.PolicyResult{Status: core.StatusFail, ResourcesFailed: 2, ResourcesEvaluated: 9, Violations: []core.Violation{{Reason: testViolationBucketOpen}}},
			want:   "2 of 9 resources failed, e.g. bucket is public",
		},
		{
			name:   "skip is silent — the scope view explains skips",
			result: core.PolicyResult{Status: core.StatusSkip},
			want:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := core.ResultReason(&tc.result); got != tc.want {
				t.Errorf("ResultReason() = %q; want %q", got, tc.want)
			}
		})
	}
}

// TestResultReason_VacuousPassSurvivesJSONRoundTrip is the regression
// that motivated moving this helper into core.
//
// The evaluator writes Diag["vacuous_clauses"] as a real []string, so an
// in-process type assertion to []string works — which is why `check` has
// always explained a vacuous pass correctly. The report package reads the
// same result back out of the vault's result.json, where Diag is
// map[string]any and the value decodes as []any. A []string-only
// assertion silently fails there, so the one pass most worth explaining
// would render as a blank cell in an auditor's report while `check`
// explained it fine.
func TestResultReason_VacuousPassSurvivesJSONRoundTrip(t *testing.T) {
	inProcess := core.PolicyResult{
		Status: core.StatusPass,
		Diag:   map[string]any{"vacuous_clauses": []string{"buckets", "keys"}},
	}
	want := core.ResultReason(&inProcess)
	if !strings.Contains(want, "buckets, keys") {
		t.Fatalf("in-process reason did not name the slots: %q", want)
	}

	body, err := json.Marshal(inProcess)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundTripped core.PolicyResult
	if err := json.Unmarshal(body, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := core.ResultReason(&roundTripped); got != want {
		t.Errorf("after a vault round-trip ResultReason() = %q; want the same as in-process %q", got, want)
	}
}

// TestResultReason_Truncates keeps one pathological violation message
// from blowing up a summary line.
func TestResultReason_Truncates(t *testing.T) {
	long := strings.Repeat("x", 500)
	got := core.ResultReason(&core.PolicyResult{
		Status:     core.StatusFail,
		Violations: []core.Violation{{Reason: long}},
	})
	if !strings.HasSuffix(got, "…") {
		t.Errorf("ResultReason() = %q; want a trailing ellipsis", got)
	}
	if n := len([]rune(got)); n > 241 {
		t.Errorf("ResultReason() returned %d runes; want <= 241 (240 + ellipsis)", n)
	}
}
