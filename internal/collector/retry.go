package collector

import (
	"context"
	"fmt"
	"time"
)

// RetryPolicy controls per-slot retry behavior in the collector. The
// orchestrator picks the policy from the run mode: PR runs use
// generous retry (blocking a developer's PR on a 30s AWS hiccup is
// worse than waiting), scheduled runs use fast-fail (the next
// scheduled run will pick up what was missed), manual runs do not
// retry (current behavior, single attempt).
//
// MaxAttempts counts the total number of tries including the first.
// 0 or 1 disables retry. Backoff[i] is slept after the i'th failure
// (zero-indexed). When the schedule is shorter than the attempt
// count the final value is reused for the remaining waits.
type RetryPolicy struct {
	MaxAttempts int
	Backoff     []time.Duration
}

// Per-mode default policies. Total wall-clock budget per slot:
// PR mode = ~8 min, scheduled = ~2 min, none = 0.
var (
	RetryPR = RetryPolicy{
		MaxAttempts: 5,
		Backoff: []time.Duration{
			5 * time.Second,
			15 * time.Second,
			45 * time.Second,
			2 * time.Minute,
			5 * time.Minute,
		},
	}
	RetryScheduled = RetryPolicy{
		MaxAttempts: 3,
		Backoff: []time.Duration{
			10 * time.Second,
			30 * time.Second,
			90 * time.Second,
		},
	}
	RetryNone = RetryPolicy{MaxAttempts: 1}
)

// withRetry calls fn up to p.MaxAttempts times, sleeping the
// configured backoff between failures. Returns nil as soon as fn
// succeeds; returns a wrapped error after the last attempt fails.
// Respects ctx cancellation during backoff (the next failure is
// reported with the cancellation cause).
func withRetry(ctx context.Context, p RetryPolicy, fn func() error) error {
	attempts := p.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			d := backoffAt(p.Backoff, i-1)
			if d > 0 {
				select {
				case <-ctx.Done():
					return fmt.Errorf("collector: retry canceled after %d attempts: %w", i, ctx.Err())
				case <-time.After(d):
				}
			}
		}
		if err := fn(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if attempts == 1 {
		return lastErr
	}
	return fmt.Errorf("after %d attempts: %w", attempts, lastErr)
}

// backoffAt returns the wait duration for the idx'th retry (0 = wait
// before attempt #2). When the configured schedule is shorter than
// idx+1, the last value is reused indefinitely — callers can omit
// the tail and rely on the final delay carrying through.
func backoffAt(schedule []time.Duration, idx int) time.Duration {
	if len(schedule) == 0 {
		return 0
	}
	if idx >= len(schedule) {
		return schedule[len(schedule)-1]
	}
	return schedule[idx]
}
