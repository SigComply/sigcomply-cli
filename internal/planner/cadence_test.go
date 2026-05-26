package planner_test

import (
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

func TestDueCadences_EmptyStateAllDue(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	got := planner.DueCadences(nil, now)
	want := planner.ScheduledCadences()
	if len(got) != len(want) {
		t.Fatalf("empty state: got %d cadences (%v); want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cadence[%d] = %q; want %q (order matters)", i, got[i], want[i])
		}
	}
}

func TestDueCadences_ContinuousAndHourlyAlwaysDue(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	// Just ran every cadence five seconds ago.
	last := map[string]time.Time{
		"continuous": now.Add(-5 * time.Second),
		"hourly":     now.Add(-5 * time.Second),
		"daily":      now.Add(-5 * time.Second),
		"weekly":     now.Add(-5 * time.Second),
		"monthly":    now.Add(-5 * time.Second),
		"quarterly":  now.Add(-5 * time.Second),
		"annual":     now.Add(-5 * time.Second),
	}
	got := planner.DueCadences(last, now)
	if !containsAll(got, []string{"continuous", "hourly"}) {
		t.Errorf("continuous + hourly must always fire; got %v", got)
	}
	for _, c := range []string{"daily", "weekly", "monthly", "quarterly", "annual"} {
		if contains(got, c) {
			t.Errorf("cadence %q should NOT be due so soon after last success; got %v", c, got)
		}
	}
}

func TestDueCadences_DailyDueAfter23h(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		last time.Time
		due  bool
	}{
		{"22h ago — not due (still inside slack window)", now.Add(-22 * time.Hour), false},
		{"23h ago — due (interval boundary, drift slack respected)", now.Add(-23 * time.Hour), true},
		{"25h ago — clearly due", now.Add(-25 * time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := planner.DueCadences(map[string]time.Time{"daily": tc.last}, now)
			has := contains(got, "daily")
			if has != tc.due {
				t.Errorf("daily due=%v; want %v (last=%v, now=%v)", has, tc.due, tc.last, now)
			}
		})
	}
}

func TestDueCadences_WeeklyRespectsCronDrift(t *testing.T) {
	// Scenario from the design notes: scheduled run was supposed to
	// fire Sunday 00:00 UTC, but GitHub Actions delayed it to Monday
	// 00:07 UTC. State-based scheduling must NOT skip the week.
	lastSundayMidnight := time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC)
	nextRunDriftedLate := time.Date(2026, 5, 24, 0, 7, 0, 0, time.UTC)
	got := planner.DueCadences(map[string]time.Time{"weekly": lastSundayMidnight}, nextRunDriftedLate)
	if !contains(got, "weekly") {
		t.Errorf("weekly must fire across a 7d cron-drift gap; got %v", got)
	}
}

func TestDueCadences_QuarterlyVsAnnualDifferentiation(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	last := map[string]time.Time{
		"quarterly": now.Add(-100 * 24 * time.Hour), // >89d23h → due
		"annual":    now.Add(-100 * 24 * time.Hour), // <364d23h → NOT due
	}
	got := planner.DueCadences(last, now)
	if !contains(got, "quarterly") {
		t.Errorf("quarterly should be due at 100d; got %v", got)
	}
	if contains(got, "annual") {
		t.Errorf("annual should NOT be due at 100d; got %v", got)
	}
}

func TestDueCadences_ZeroTimeTreatedAsNeverRun(t *testing.T) {
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	// Key exists but timestamp is zero — defensively treated as
	// never-run (matches what a freshly-deserialized state file with
	// a missing nested field would produce).
	got := planner.DueCadences(map[string]time.Time{"weekly": {}}, now)
	if !contains(got, "weekly") {
		t.Errorf("zero-time should be treated as never-run; got %v", got)
	}
}

func TestCadenceInterval_KnownCadences(t *testing.T) {
	cases := []struct {
		cadence string
		want    time.Duration
	}{
		{"continuous", 0},
		{"hourly", 0},
		{"daily", 23 * time.Hour},
		{"weekly", 6*24*time.Hour + 23*time.Hour},
		{"monthly", 29*24*time.Hour + 23*time.Hour},
		{"quarterly", 89*24*time.Hour + 23*time.Hour},
		{"annual", 364*24*time.Hour + 23*time.Hour},
		{"unknown-cadence", 0},
	}
	for _, tc := range cases {
		if got := planner.CadenceInterval(tc.cadence); got != tc.want {
			t.Errorf("CadenceInterval(%q) = %v; want %v", tc.cadence, got, tc.want)
		}
	}
}

// containsAll reports whether every element of want appears in got.
func containsAll(got, want []string) bool {
	for _, w := range want {
		if !contains(got, w) {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
