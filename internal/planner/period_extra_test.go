package planner_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// An invalid fiscal_calendar.starts month name surfaces a clear error.
func TestDerivePeriod_FiscalYear_InvalidMonthErrors(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{Type: "fiscal_year", Starts: "smarch"},
	}
	_, err := planner.DerivePeriod(cfg, time.Now())
	if err == nil || !strings.Contains(err.Error(), "invalid fiscal_calendar.starts") {
		t.Errorf("want invalid-month error; got %v", err)
	}
}

// An empty fiscal_calendar.starts defaults to January.
func TestDerivePeriod_FiscalYear_EmptyStartsDefaultsJanuary(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{Type: "fiscal_year"}, // Starts empty
	}
	commit := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	p, err := planner.DerivePeriod(cfg, commit)
	if err != nil {
		t.Fatalf("DerivePeriod: %v", err)
	}
	// Jan-start fiscal year named after the calendar year of the commit.
	if p.ID != "FY2026" {
		t.Errorf("ID = %q; want FY2026", p.ID)
	}
}

// A commit before the fiscal-year boundary belongs to the prior FY.
func TestDerivePeriod_FiscalYear_BeforeBoundary(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{Type: "fiscal_year", Starts: "april"},
	}
	// March is before the April boundary → belongs to FY2025.
	commit := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	p, err := planner.DerivePeriod(cfg, commit)
	if err != nil {
		t.Fatalf("DerivePeriod: %v", err)
	}
	if p.ID != "FY2025" {
		t.Errorf("ID = %q; want FY2025 (commit before April boundary)", p.ID)
	}
}

// A custom period with an unparseable start date surfaces an error.
func TestDerivePeriod_Custom_InvalidStartDateErrors(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{
			Type:    "custom",
			Periods: []spec.CustomPeriod{{ID: "P1", Start: "not-a-date", End: "2026-01-31"}},
		},
	}
	commit := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	_, err := planner.DerivePeriod(cfg, commit)
	if err == nil || !strings.Contains(err.Error(), "invalid start") {
		t.Errorf("want invalid-start error; got %v", err)
	}
}

// A custom period with an unparseable end date surfaces an error.
func TestDerivePeriod_Custom_InvalidEndDateErrors(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{
			Type:    "custom",
			Periods: []spec.CustomPeriod{{ID: "P1", Start: "2026-01-04", End: "garbage"}},
		},
	}
	commit := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	_, err := planner.DerivePeriod(cfg, commit)
	if err == nil || !strings.Contains(err.Error(), "invalid end") {
		t.Errorf("want invalid-end error; got %v", err)
	}
}
