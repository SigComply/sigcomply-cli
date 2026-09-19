package collector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/fileconv"
)

func TestWithRetry_SucceedsFirstAttempt(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), RetryPolicy{MaxAttempts: 3, Backoff: []time.Duration{0, 0}}, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d; want 1", calls)
	}
}

func TestWithRetry_SucceedsOnNthAttempt(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), RetryPolicy{MaxAttempts: 5, Backoff: []time.Duration{0, 0, 0, 0}}, func() error {
		calls++
		if calls < 3 {
			return errors.New("flake")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d; want 3 (succeed on third)", calls)
	}
}

func TestWithRetry_ExhaustsAttempts(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), RetryPolicy{MaxAttempts: 4, Backoff: []time.Duration{0, 0, 0}}, func() error {
		calls++
		return errors.New("dead")
	})
	if err == nil {
		t.Fatal("expected exhaustion error; got nil")
	}
	if calls != 4 {
		t.Errorf("calls = %d; want 4", calls)
	}
	if !strings.Contains(err.Error(), "after 4 attempts") {
		t.Errorf("error should mention attempt count; got %q", err.Error())
	}
}

func TestWithRetry_MaxAttemptsZeroBehavesAsOne(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), RetryPolicy{}, func() error {
		calls++
		return errors.New("dead")
	})
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if calls != 1 {
		t.Errorf("calls = %d; want 1 (zero MaxAttempts = no retry)", calls)
	}
	// With only one attempt, the wrapper should NOT prefix "after N attempts".
	if strings.Contains(err.Error(), "after 1 attempts") {
		t.Errorf("single-attempt error should not be wrapped; got %q", err.Error())
	}
}

func TestWithRetry_RespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	policy := RetryPolicy{MaxAttempts: 5, Backoff: []time.Duration{1 * time.Hour, 1 * time.Hour, 1 * time.Hour, 1 * time.Hour}}

	// Cancel immediately so the first backoff sleep is interrupted.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := withRetry(ctx, policy, func() error {
		calls++
		return errors.New("flake")
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected cancellation error; got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should wrap context.Canceled; got %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d; want 1 (cancel interrupted before second attempt)", calls)
	}
	if elapsed > 1*time.Second {
		t.Errorf("withRetry took %v; should have returned immediately on cancel", elapsed)
	}
}

func TestWithRetry_LastBackoffReusedWhenScheduleShort(t *testing.T) {
	// Schedule is [0] but MaxAttempts is 4. We expect three retries
	// total, each using the last (and only) backoff value of 0.
	calls := 0
	err := withRetry(context.Background(), RetryPolicy{MaxAttempts: 4, Backoff: []time.Duration{0}}, func() error {
		calls++
		return errors.New("dead")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 4 {
		t.Errorf("calls = %d; want 4 (short schedule must not cap attempts)", calls)
	}
}

func TestBackoffAt_TableScan(t *testing.T) {
	schedule := []time.Duration{1 * time.Second, 3 * time.Second, 7 * time.Second}
	cases := []struct {
		idx  int
		want time.Duration
	}{
		{0, 1 * time.Second},
		{1, 3 * time.Second},
		{2, 7 * time.Second},
		{3, 7 * time.Second}, // beyond schedule → reuse last
		{99, 7 * time.Second},
	}
	for _, tc := range cases {
		if got := backoffAt(schedule, tc.idx); got != tc.want {
			t.Errorf("backoffAt(idx=%d) = %v; want %v", tc.idx, got, tc.want)
		}
	}
	if got := backoffAt(nil, 0); got != 0 {
		t.Errorf("backoffAt(nil, 0) = %v; want 0", got)
	}
}

func TestPredefinedPoliciesShape(t *testing.T) {
	// Defensive: ensure the predefined policies stay structurally
	// sensible. Hand-tuned numbers from the design doc.
	if RetryPR.MaxAttempts <= RetryScheduled.MaxAttempts {
		t.Errorf("PR policy should be more generous than Scheduled (attempts: PR=%d, Scheduled=%d)",
			RetryPR.MaxAttempts, RetryScheduled.MaxAttempts)
	}
	if RetryNone.MaxAttempts != 1 {
		t.Errorf("RetryNone.MaxAttempts = %d; want 1", RetryNone.MaxAttempts)
	}
	for name, p := range map[string]RetryPolicy{"PR": RetryPR, "Scheduled": RetryScheduled} {
		if len(p.Backoff) < p.MaxAttempts-1 {
			t.Errorf("%s: backoff length %d < MaxAttempts-1 (%d)", name, len(p.Backoff), p.MaxAttempts-1)
		}
	}
}

// --- retryable vs terminal classification -------------------------

func TestWithRetry_TerminalErrorStopsImmediately(t *testing.T) {
	calls := 0
	// An hour of backoff: if the terminal error did not short-circuit,
	// this test would hang rather than fail fast.
	policy := RetryPolicy{MaxAttempts: 5, Backoff: []time.Duration{time.Hour, time.Hour, time.Hour, time.Hour}}
	terminal := &sources.APIError{Source: testSourceGitHub, StatusCode: 403, Message: "/orgs/acme: 403 Forbidden: insufficient scope"}

	start := time.Now()
	err := withRetry(context.Background(), policy, func() error {
		calls++
		return terminal
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if calls != 1 {
		t.Errorf("calls = %d; want 1 (a 403 will not clear on retry)", calls)
	}
	if elapsed > time.Second {
		t.Errorf("withRetry took %v; a terminal error must not sleep the backoff", elapsed)
	}
	if strings.Contains(err.Error(), "after") && strings.Contains(err.Error(), "attempts") {
		t.Errorf("terminal error must not be wrapped as retried; got %q", err.Error())
	}
	if !errors.Is(err, terminal) {
		t.Errorf("terminal error must be returned as-is; got %v", err)
	}
}

func TestWithRetry_RetryableAPIErrorExhaustsAttempts(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), RetryPolicy{MaxAttempts: 4, Backoff: []time.Duration{0, 0, 0}}, func() error {
		calls++
		return &sources.APIError{Source: testSourceOkta, StatusCode: 429, Message: "/api/v1/users: 429 Too Many Requests"}
	})
	if err == nil {
		t.Fatal("expected exhaustion error; got nil")
	}
	if calls != 4 {
		t.Errorf("calls = %d; want 4 (429 is transient)", calls)
	}
	if !strings.Contains(err.Error(), "after 4 attempts") {
		t.Errorf("exhausted retryable error should mention the attempt count; got %q", err.Error())
	}
}

func TestWithRetry_UnclassifiedErrorExhaustsAttempts(t *testing.T) {
	// The load-bearing non-breaking property: every source we have not
	// converted keeps its pre-classification behavior.
	calls := 0
	err := withRetry(context.Background(), RetryPolicy{MaxAttempts: 3, Backoff: []time.Duration{0, 0}}, func() error {
		calls++
		return errors.New("some unconverted vendor error")
	})
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if calls != 3 {
		t.Errorf("calls = %d; want 3 (unclassified must stay retryable)", calls)
	}
}

func TestWithRetry_TerminalClassificationSurvivesWrapping(t *testing.T) {
	// Plugins wrap their HTTP errors with %w on the way out; the
	// classifier has to see through that.
	calls := 0
	err := withRetry(context.Background(), RetryPolicy{MaxAttempts: 5, Backoff: []time.Duration{time.Hour}}, func() error {
		calls++
		return fmt.Errorf("list roster users (needs the User.Read.All permission): %w",
			&sources.APIError{Source: "azure.entra", StatusCode: 401, Message: "401 Unauthorized"})
	})
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if calls != 1 {
		t.Errorf("calls = %d; want 1 (terminal error wrapped by the plugin)", calls)
	}
}

func TestWithRetry_UnsupportedFileTypeIsTerminal(t *testing.T) {
	// A .docx in a manual-evidence folder used to cost five attempts
	// and three minutes of sleep on a PR run.
	calls := 0
	err := withRetry(context.Background(), RetryPR, func() error {
		calls++
		return &fileconv.UnsupportedTypeError{Filename: "access-review.docx", Ext: ".docx"}
	})
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if calls != 1 {
		t.Errorf("calls = %d; want 1 (an unconvertible extension never converts)", calls)
	}
}

func TestWithRetry_ContextCancelStillWinsOverClassification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	policy := RetryPolicy{MaxAttempts: 5, Backoff: []time.Duration{time.Hour, time.Hour, time.Hour, time.Hour}}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// A retryable classification must not stop the cancellation path
	// from firing during backoff.
	err := withRetry(ctx, policy, func() error {
		calls++
		return &sources.APIError{Source: testSourceGitHub, StatusCode: 503, Message: "503 Service Unavailable"}
	})
	if err == nil {
		t.Fatal("expected cancellation error; got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should wrap context.Canceled; got %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d; want 1", calls)
	}
}
