package planner_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

func TestDerivePeriod_CalendarQuarter(t *testing.T) {
	cases := []struct {
		commit string
		want   string
	}{
		{"2026-01-15T13:55:00Z", "2026-Q1"},
		{"2026-02-15T13:55:00Z", "2026-Q1"},
		{"2026-03-31T23:59:59Z", "2026-Q1"},
		{"2026-04-01T00:01:00Z", "2026-Q2"},
		{"2026-06-30T00:00:00Z", "2026-Q2"},
		{"2026-07-01T00:00:00Z", "2026-Q3"},
		{"2026-10-01T00:00:00Z", "2026-Q4"},
		{"2026-12-31T23:59:59Z", "2026-Q4"},
	}
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{Type: "calendar_quarter"},
		TimeBasis:      "commit",
	}
	for _, tc := range cases {
		t.Run(tc.commit, func(t *testing.T) {
			commit, err := time.Parse(time.RFC3339, tc.commit)
			if err != nil {
				t.Fatalf("parse commit: %v", err)
			}
			p, err := planner.DerivePeriod(cfg, commit)
			if err != nil {
				t.Fatalf("DerivePeriod: %v", err)
			}
			if p.ID != tc.want {
				t.Errorf("ID = %q; want %q", p.ID, tc.want)
			}
		})
	}
}

func TestDerivePeriod_DefaultsToCalendarQuarter(t *testing.T) {
	// Empty fiscal_calendar.type → defaults to calendar_quarter.
	commit, err := time.Parse(time.RFC3339, "2026-02-15T13:55:00Z")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p, err := planner.DerivePeriod(&spec.PeriodConfig{}, commit)
	if err != nil {
		t.Fatalf("DerivePeriod: %v", err)
	}
	if p.ID != "2026-Q1" {
		t.Errorf("ID = %q; want 2026-Q1", p.ID)
	}
}

func TestDerivePeriod_FiscalYearApril(t *testing.T) {
	cases := []struct {
		commit string
		want   string
	}{
		{"2026-04-01T00:00:00Z", "FY2026"},
		{"2026-03-31T23:59:59Z", "FY2025"},
		{"2026-12-31T23:59:59Z", "FY2026"},
		{"2027-03-15T00:00:00Z", "FY2026"},
	}
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{
			Type:   "fiscal_year",
			Starts: "april",
		},
		TimeBasis: "commit",
	}
	for _, tc := range cases {
		t.Run(tc.commit, func(t *testing.T) {
			commit, err := time.Parse(time.RFC3339, tc.commit)
			if err != nil {
				t.Fatalf("parse commit: %v", err)
			}
			p, err := planner.DerivePeriod(cfg, commit)
			if err != nil {
				t.Fatalf("DerivePeriod: %v", err)
			}
			if p.ID != tc.want {
				t.Errorf("ID = %q; want %q", p.ID, tc.want)
			}
		})
	}
}

func TestDerivePeriod_Custom(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{
			Type: "custom",
			Periods: []spec.CustomPeriod{
				{ID: "2026-P01", Start: "2026-01-04", End: "2026-01-31"},
				{ID: "2026-P02", Start: "2026-02-01", End: "2026-02-28"},
			},
		},
	}
	commit, err := time.Parse(time.RFC3339, "2026-02-10T00:00:00Z")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p, err := planner.DerivePeriod(cfg, commit)
	if err != nil {
		t.Fatalf("DerivePeriod: %v", err)
	}
	if p.ID != "2026-P02" {
		t.Errorf("ID = %q; want 2026-P02", p.ID)
	}
}

func TestDerivePeriod_CustomNoMatch(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{
			Type: "custom",
			Periods: []spec.CustomPeriod{
				{ID: "2026-P01", Start: "2026-01-04", End: "2026-01-31"},
			},
		},
	}
	commit, err := time.Parse(time.RFC3339, "2026-03-10T00:00:00Z")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = planner.DerivePeriod(cfg, commit)
	if err == nil {
		t.Fatal("expected error when commit falls outside all configured custom periods")
	}
	if !strings.Contains(err.Error(), "does not fall in any") {
		t.Errorf("error = %q; want substring about no match", err.Error())
	}
}

func TestDerivePeriod_UnknownType(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{Type: "lunar"},
	}
	_, err := planner.DerivePeriod(cfg, time.Now())
	if err == nil {
		t.Fatal("expected error for unknown fiscal_calendar.type")
	}
}
