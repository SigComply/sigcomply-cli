package planner

import (
	"fmt"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// scheduledCadences is the canonical ordered list of named cadences a
// scheduled run considers. on_push is intentionally absent: it's the
// PR mode's axis, not a scheduled-mode cadence. The `every:<dur>`
// form is parsed separately and never appears in this list.
var scheduledCadences = []string{
	"continuous",
	"hourly",
	"daily",
	"weekly",
	"monthly",
	"quarterly",
	"annual",
}

// everyCadencePrefix is the prefix for custom interval cadences. The
// stored form is "every:<duration>" with no space, so YAML parsers
// see it as a single scalar (a colon followed by a non-space
// character is not a YAML mapping). Examples:
//
//	cadence: every:6h
//	cadence: every:30m
//	cadence: every:2h30m
//
// The duration uses Go's time.ParseDuration grammar.
const everyCadencePrefix = "every:"

// minEveryDuration is the floor for custom interval cadences. Shorter
// intervals indicate a misuse: CI runners can't dispatch faster, and
// faster cadences would just spam the API quotas. Set to 5 minutes —
// the same floor most monitoring systems pick.
const minEveryDuration = 5 * time.Minute

// CadenceInterval returns the minimum elapsed time after a successful
// run before a cadence is due again. Intervals are deliberately
// shorter than their nominal values to absorb CI cron drift: GitHub
// Actions and GitLab CI commonly fire scheduled jobs 5–15 minutes
// late under load, and a strict 24h gate would silently skip days
// when drift crosses midnight. A 1h slack per cadence is enough for
// both platforms in practice.
//
// continuous and hourly return 0 — the caller (DueCadences) treats
// them as "always due" in any scheduled run, since the scheduled
// job runs at most once per day and sub-daily cadences effectively
// fire on every run.
//
// For `every:<duration>` cadences the returned interval is the
// parsed duration verbatim (no slack — the user picked the number).
// An unparseable `every:` value returns 0, which the planner treats
// as "always due" so a misconfigured cadence is loud rather than
// silently disabling the policy.
func CadenceInterval(cadence string) time.Duration {
	if d, ok, err := parseEveryCadence(cadence); ok {
		// Malformed every:<dur> cadences are rejected by the spec
		// validator at config-load time; if one slips through here we
		// fall through to 0 (always due) — making the misconfigured
		// policy loud rather than silently disabled.
		if err == nil {
			return d
		}
		return 0
	}
	switch cadence {
	case "continuous", "hourly":
		return 0
	case "daily":
		return 23 * time.Hour
	case "weekly":
		return 6*24*time.Hour + 23*time.Hour
	case "monthly":
		return 29*24*time.Hour + 23*time.Hour
	case "quarterly":
		return 89*24*time.Hour + 23*time.Hour
	case "annual":
		return 364*24*time.Hour + 23*time.Hour
	}
	return 0
}

// IsValidCadence reports whether s is a recognized cadence — either
// a named cadence (continuous, hourly, …, annual) or a parseable
// `every:<duration>` value. Used by the spec validator and the
// planner's lint warnings.
func IsValidCadence(s string) bool {
	if s == "" {
		return false
	}
	if _, ok, err := parseEveryCadence(s); ok {
		return err == nil
	}
	for _, c := range scheduledCadences {
		if c == s {
			return true
		}
	}
	return false
}

// ValidateCadence returns nil iff s is recognized. For invalid input
// the error message lists the valid forms.
func ValidateCadence(s string) error {
	if IsValidCadence(s) {
		return nil
	}
	if strings.HasPrefix(s, everyCadencePrefix) {
		_, _, err := parseEveryCadence(s)
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("invalid cadence %q (want continuous|hourly|daily|weekly|monthly|quarterly|annual or every:<duration>)", s)
}

// parseEveryCadence parses an `every:<duration>` string and returns
// (duration, true, nil) when the prefix matches. Returns (0, false,
// nil) when the input is not an every-form. Returns (0, true, err)
// when the input matches the prefix but the duration is unparseable
// or below the floor — callers receive both an indication of intent
// and a precise error.
func parseEveryCadence(s string) (time.Duration, bool, error) {
	if !strings.HasPrefix(s, everyCadencePrefix) {
		return 0, false, nil
	}
	raw := strings.TrimPrefix(s, everyCadencePrefix)
	if raw == "" {
		return 0, true, fmt.Errorf("cadence %q: missing duration after %q", s, everyCadencePrefix)
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, true, fmt.Errorf("cadence %q: invalid duration: %w", s, err)
	}
	if d <= 0 {
		return 0, true, fmt.Errorf("cadence %q: duration must be positive", s)
	}
	if d < minEveryDuration {
		return 0, true, fmt.Errorf("cadence %q: duration %s is below floor %s (CI cannot meaningfully dispatch faster)", s, d, minEveryDuration)
	}
	return d, true, nil
}

// NextDueAt computes the wall-clock time after which a policy with
// the given cadence and last-pass timestamp is due to be re-
// evaluated. Returns the zero time for "continuous" / "hourly" and
// for never-run policies — both translate to "always due" in the
// planner.
//
// For named cadences NextDueAt = lastPass + CadenceInterval (with
// the embedded cron-drift slack). For `every:<duration>` cadences
// NextDueAt = lastPass + duration exactly.
func NextDueAt(cadence string, lastPass time.Time) time.Time {
	if lastPass.IsZero() {
		return time.Time{}
	}
	interval := CadenceInterval(cadence)
	if interval == 0 {
		return time.Time{}
	}
	return lastPass.Add(interval).UTC()
}

// IsDue reports whether a policy with the given cadence and prior
// state is due at `now`. The decision composes three layers:
//
//  1. First run (zero LastRunAt) → due.
//  2. on_fail_retry: prior status was not pass → due regardless of
//     cadence.
//  3. Cadence elapsed: now - LastPassAt >= CadenceInterval(cadence) → due.
//
// Content-hash invalidation (LastPolicyHash mismatch with current
// hash) is handled by the planner outside this function so the same
// logic also drives `sigcomply why`-style introspection without
// needing the current hash.
func IsDue(cadence string, state *core.PolicyState, now time.Time) bool {
	if state == nil || state.IsFirstRun() {
		return true
	}
	// on_fail_retry: any prior non-pass terminal status requires
	// re-evaluation on the next run regardless of cadence.
	if state.LastRunStatus != core.StatusPass {
		return true
	}
	interval := CadenceInterval(cadence)
	if interval == 0 {
		return true
	}
	last := state.LastPassAt
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= interval
}

// DueReason returns a short human-readable reason string for why a
// policy is (or isn't) due at `now` under the given cadence and
// state. Powers the `sigcomply why` command and the run-level
// "skipped because…" diagnostics. Reasons are deterministic given
// (cadence, state, now) and free of resource identifiers.
func DueReason(cadence string, state *core.PolicyState, now time.Time) string {
	if state == nil || state.IsFirstRun() {
		return "first run; never evaluated before"
	}
	if state.LastRunStatus != core.StatusPass {
		return fmt.Sprintf("prior status was %q; on_fail_retry forces re-evaluation", state.LastRunStatus)
	}
	interval := CadenceInterval(cadence)
	if interval == 0 {
		return fmt.Sprintf("cadence %q has zero interval; always due", cadence)
	}
	elapsed := now.Sub(state.LastPassAt)
	if elapsed >= interval {
		return fmt.Sprintf("%s since last pass exceeds cadence interval %s", elapsed.Round(time.Second), interval)
	}
	return fmt.Sprintf("only %s since last pass; cadence interval %s not yet elapsed (next due %s)",
		elapsed.Round(time.Second), interval, NextDueAt(cadence, state.LastPassAt).Format(time.RFC3339))
}

// DueCadences returns the set of NAMED cadences that should fire in
// a scheduled run given the last-success-by-cadence map and the
// current time. This function is retained for the orchestrator's
// legacy --cadences filter resolution. The per-policy due decision
// (which is now authoritative) is in IsDue above.
//
// A cadence is due when (now - last_success) >= CadenceInterval. A
// cadence absent from the map or with a zero timestamp is treated
// as never-run and therefore due. continuous and hourly are always
// due. `every:<duration>` cadences are NOT considered here — they
// have no canonical bucket; each policy with an every-cadence
// drives its own due decision via IsDue.
//
// The returned slice is in the canonical scheduledCadences order so
// callers iterating it observe deterministic behavior across runs.
func DueCadences(lastSuccess map[string]time.Time, now time.Time) []string {
	due := make([]string, 0, len(scheduledCadences))
	for _, c := range scheduledCadences {
		interval := CadenceInterval(c)
		if interval == 0 {
			due = append(due, c)
			continue
		}
		last, ok := lastSuccess[c]
		if !ok || last.IsZero() {
			due = append(due, c)
			continue
		}
		if now.Sub(last) >= interval {
			due = append(due, c)
		}
	}
	return due
}

// ScheduledCadences returns a copy of the canonical named-cadence
// list, for callers that need to enumerate every scheduled-mode
// cadence (e.g. to seed an empty state file or to validate config).
// Excludes `every:<duration>` forms by design.
func ScheduledCadences() []string {
	out := make([]string, len(scheduledCadences))
	copy(out, scheduledCadences)
	return out
}
