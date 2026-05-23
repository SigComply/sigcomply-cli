package planner

import (
	"fmt"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// DerivePeriod computes the audit period for a commit timestamp under
// the project's fiscal_calendar configuration. The function is pure:
// the only inputs are the configured calendar and the commit time;
// the only output is a stamped Period. See docs/architecture/01-
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

func calendarQuarter(t time.Time, timeBasis string) Period {
	utc := t.UTC()
	year := utc.Year()
	quarter := (int(utc.Month())-1)/3 + 1
	startMonth := time.Month((quarter-1)*3 + 1)
	start := time.Date(year, startMonth, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 3, 0).Add(-time.Nanosecond)
	return Period{
		ID:        fmt.Sprintf("%d-Q%d", year, quarter),
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
			return Period{
				ID:        p.ID,
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
