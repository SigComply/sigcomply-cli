package planner

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// PeriodTime selects the clock every period derivation in a run is
// measured on, honoring period.time_basis. The default, "commit", ties
// the audit window to the HEAD commit's timestamp so a replayed run
// reproduces the same period; "wall_clock" ties it to the run's start.
//
// A zero now falls back to the commit time: a caller with no run clock
// must not silently derive a year-1 period.
func PeriodTime(cfg *spec.PeriodConfig, commit, now time.Time) time.Time {
	if cfg != nil && cfg.TimeBasis == "wall_clock" && !now.IsZero() {
		return now
	}
	return commit
}

// DerivePeriod computes the run's audit period for a timestamp under
// the project's fiscal_calendar configuration. The function is pure:
// the only inputs are the configured calendar and the time; the only
// output is a stamped Period. Pass the time through PeriodTime so the
// project's time_basis is honored. See docs/architecture/01-
// conceptual-model.md §Period for the model.
func DerivePeriod(cfg *spec.PeriodConfig, commit time.Time) (Period, error) {
	cal := cfg.FiscalCalendar
	if cal.Type == "" {
		// Default per docs/architecture/08-project-config.md.
		cal.Type = "calendar_quarter"
	}
	switch cal.Type {
	case "calendar_quarter":
		return calendarQuarter(commit, cfg.TimeBasis), nil
	case "fiscal_year":
		return fiscalYear(commit, cal.Starts, cfg.TimeBasis)
	case "custom":
		return customPeriod(commit, cal.Periods, cfg.TimeBasis)
	default:
		return Period{}, fmt.Errorf("planner: unknown fiscal_calendar.type %q", cal.Type)
	}
}

// CadencePeriod computes the audit window a policy of the given cadence
// files its manual evidence under. It is the folder scheme documented in
// docs/configuration.md §Manual evidence, and it is deliberately NOT the
// run's period: an annual attestation uploaded in January has to satisfy
// a December run, which it cannot do from a folder that turns over every
// quarter.
//
// The run's own period is unaffected — the vault run root, manifest.json,
// summary.json, the cloud payload and PolicyState.LastPeriodID all keep
// DerivePeriod's answer. Only the customer's upload folder, and the
// temporal window checked against it, follow the cadence.
//
// The rule, by fiscal_calendar.type:
//
//	cadence    calendar_quarter   fiscal_year   custom
//	daily      2026-01-15         2026-01-15    run period
//	weekly     2026-W03           2026-W03      run period
//	monthly    2026-01            2026-01       run period
//	quarterly  2026-Q1            2026-Q1       run period
//	annual     2026               FY2026        run period
//
// A fiscal year is the project's declared annual window, so the annual
// cadence honors it. Nothing in the config subdivides a fiscal year, so
// shorter cadences stay calendar-aligned — which also keeps them
// identical to the keys the Evidence SPA derives client-side in
// src/lib/period.ts. A custom calendar names its own windows and cannot
// be subdivided at all, and continuous/hourly/every:<duration> name no
// calendar window, so both keep the run's period rather than being
// rounded into one.
func CadencePeriod(cfg *spec.PeriodConfig, t time.Time, cadence string) (Period, error) {
	run, err := DerivePeriod(cfg, t)
	if err != nil {
		return Period{}, err
	}
	if cfg.FiscalCalendar.Type == "custom" {
		return run, nil
	}
	switch cadence {
	case cadenceDaily:
		return dayPeriod(t, cfg.TimeBasis), nil
	case cadenceWeekly:
		return weekPeriod(t, cfg.TimeBasis), nil
	case cadenceMonthly:
		return monthPeriod(t, cfg.TimeBasis), nil
	case cadenceQuarterly:
		return calendarQuarter(t, cfg.TimeBasis), nil
	case cadenceAnnual:
		if cfg.FiscalCalendar.Type == "fiscal_year" {
			return run, nil
		}
		return yearPeriod(t, cfg.TimeBasis), nil
	default:
		return run, nil
	}
}

func dayPeriod(t time.Time, timeBasis string) Period {
	utc := t.UTC()
	start := time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	const layout = "2006-01-02"
	return Period{
		ID:        start.Format(layout),
		PriorID:   start.AddDate(0, 0, -1).Format(layout),
		Start:     start,
		End:       start.AddDate(0, 0, 1).Add(-time.Nanosecond),
		TimeBasis: defaultBasis(timeBasis),
	}
}

// weekPeriod anchors on Monday and labels with the ISO-8601 week, so the
// days either side of New Year land in the same folder as the rest of
// their week — 2026-01-01 is a Thursday and belongs to 2026-W01, which
// starts 2025-12-29.
func weekPeriod(t time.Time, timeBasis string) Period {
	utc := t.UTC()
	start := time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	// Go's Weekday is Sunday=0; shift so Monday=0.
	start = start.AddDate(0, 0, -((int(start.Weekday()) + 6) % 7))
	return Period{
		ID:        isoWeekID(start),
		PriorID:   isoWeekID(start.AddDate(0, 0, -7)),
		Start:     start,
		End:       start.AddDate(0, 0, 7).Add(-time.Nanosecond),
		TimeBasis: defaultBasis(timeBasis),
	}
}

func isoWeekID(t time.Time) string {
	year, week := t.ISOWeek()
	return fmt.Sprintf("%d-W%02d", year, week)
}

func monthPeriod(t time.Time, timeBasis string) Period {
	utc := t.UTC()
	start := time.Date(utc.Year(), utc.Month(), 1, 0, 0, 0, 0, time.UTC)
	const layout = "2006-01"
	return Period{
		ID:        start.Format(layout),
		PriorID:   start.AddDate(0, -1, 0).Format(layout),
		Start:     start,
		End:       start.AddDate(0, 1, 0).Add(-time.Nanosecond),
		TimeBasis: defaultBasis(timeBasis),
	}
}

func yearPeriod(t time.Time, timeBasis string) Period {
	year := t.UTC().Year()
	start := time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC)
	return Period{
		ID:        strconv.Itoa(year),
		PriorID:   strconv.Itoa(year - 1),
		Start:     start,
		End:       start.AddDate(1, 0, 0).Add(-time.Nanosecond),
		TimeBasis: defaultBasis(timeBasis),
	}
}

func calendarQuarter(t time.Time, timeBasis string) Period {
	utc := t.UTC()
	year := utc.Year()
	quarter := (int(utc.Month())-1)/3 + 1
	startMonth := time.Month((quarter-1)*3 + 1)
	start := time.Date(year, startMonth, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 3, 0).Add(-time.Nanosecond)
	priorYear, priorQuarter := year, quarter-1
	if priorQuarter == 0 {
		priorYear, priorQuarter = year-1, 4
	}
	return Period{
		ID:        fmt.Sprintf("%d-Q%d", year, quarter),
		PriorID:   fmt.Sprintf("%d-Q%d", priorYear, priorQuarter),
		Start:     start,
		End:       end,
		TimeBasis: defaultBasis(timeBasis),
	}
}

func fiscalYear(t time.Time, startsMonth, timeBasis string) (Period, error) {
	month, err := parseMonth(startsMonth)
	if err != nil {
		return Period{}, err
	}
	utc := t.UTC()
	year := utc.Year()
	if utc.Month() < month {
		// Before the fiscal-year boundary: this commit belongs to the
		// fiscal year named after the prior calendar year.
		year--
	}
	start := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(1, 0, 0).Add(-time.Nanosecond)
	return Period{
		ID:        fmt.Sprintf("FY%d", year),
		PriorID:   fmt.Sprintf("FY%d", year-1),
		Start:     start,
		End:       end,
		TimeBasis: defaultBasis(timeBasis),
	}, nil
}

func customPeriod(t time.Time, periods []spec.CustomPeriod, timeBasis string) (Period, error) {
	utc := t.UTC()
	for i := range periods {
		p := &periods[i]
		start, err := time.Parse("2006-01-02", p.Start)
		if err != nil {
			return Period{}, fmt.Errorf("planner: custom period %q: invalid start %q: %w", p.ID, p.Start, err)
		}
		end, err := time.Parse("2006-01-02", p.End)
		if err != nil {
			return Period{}, fmt.Errorf("planner: custom period %q: invalid end %q: %w", p.ID, p.End, err)
		}
		// Inclusive end-of-day.
		end = end.Add(24*time.Hour - time.Nanosecond)
		if (utc.Equal(start) || utc.After(start)) && utc.Before(end.Add(time.Nanosecond)) {
			priorID := ""
			if i > 0 {
				priorID = periods[i-1].ID
			}
			return Period{
				ID:        p.ID,
				PriorID:   priorID,
				Start:     start,
				End:       end,
				TimeBasis: defaultBasis(timeBasis),
			}, nil
		}
	}
	return Period{}, fmt.Errorf("planner: commit time %s does not fall in any configured custom period", utc.Format(time.RFC3339))
}

var monthByName = map[string]time.Month{
	"january": time.January, "february": time.February, "march": time.March,
	"april": time.April, "may": time.May, "june": time.June,
	"july": time.July, "august": time.August, "september": time.September,
	"october": time.October, "november": time.November, "december": time.December,
}

func parseMonth(s string) (time.Month, error) {
	if s == "" {
		return time.January, nil
	}
	m, ok := monthByName[strings.ToLower(s)]
	if !ok {
		return 0, fmt.Errorf("planner: invalid fiscal_calendar.starts %q (want month name like \"april\")", s)
	}
	return m, nil
}

func defaultBasis(s string) string {
	if s == "" {
		return "commit"
	}
	return s
}
