package spec

import (
	"strings"
	"testing"
)

func customPeriodConfig(periods string) []byte {
	return []byte("schema_version: project.v1\nframework: soc2\nperiod:\n  fiscal_calendar:\n    type: custom\n    periods:\n" + periods)
}

// A custom period's ID becomes a vault folder and the period_id sent to
// SigComply Cloud, so it must be one safe path segment within the
// dashboard's 50-character limit; its dates must parse and run forward;
// and periods must not overlap, or a run's period depends on list order.
func TestLoadProjectConfig_CustomPeriodValidation(t *testing.T) {
	cases := []struct {
		name, periods, want string
	}{
		{"slash in id", "      - {id: \"fy/h1\", start: \"2026-01-01\", end: \"2026-06-30\"}\n", "letters, digits"},
		{"dot-dot id", "      - {id: \"..\", start: \"2026-01-01\", end: \"2026-06-30\"}\n", "letters, digits"},
		{"long id", "      - {id: \"acme-corp-fiscal-year-2026-second-half-audit-window-period\", start: \"2026-01-01\", end: \"2026-06-30\"}\n", "at most 50"},
		{"bad start", "      - {id: H1, start: \"2026-13-01\", end: \"2026-06-30\"}\n", "start"},
		{"bad end", "      - {id: H1, start: \"2026-01-01\", end: \"June\"}\n", "end"},
		{"end before start", "      - {id: H1, start: \"2026-06-30\", end: \"2026-01-01\"}\n", "before its start"},
		{"overlap", "      - {id: H1, start: \"2026-01-01\", end: \"2026-07-15\"}\n      - {id: H2, start: \"2026-07-01\", end: \"2026-12-31\"}\n", "overlap"},
		{"duplicate id", "      - {id: H1, start: \"2026-01-01\", end: \"2026-06-30\"}\n      - {id: H1, start: \"2026-07-01\", end: \"2026-12-31\"}\n", "more than once"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadProjectConfig(customPeriodConfig(c.periods))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q; got %v", c.want, err)
			}
		})
	}
}

// Periods listed out of order are sorted at load, so the prior period
// (used by the copy-of-prior-period check) is the one before in time,
// not the one before in the file.
func TestLoadProjectConfig_CustomPeriodsSortedByStart(t *testing.T) {
	cfg, err := LoadProjectConfig(customPeriodConfig(
		"      - {id: H2, start: \"2026-07-01\", end: \"2026-12-31\"}\n" +
			"      - {id: H1, start: \"2026-01-01\", end: \"2026-06-30\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Period.FiscalCalendar.Periods
	if got[0].ID != "H1" || got[1].ID != "H2" {
		t.Errorf("periods not sorted by start: %+v", got)
	}
}
