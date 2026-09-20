package planner_test

import (
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

func mustParse(t *testing.T, ts string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Fatalf("parse %q: %v", ts, err)
	}
	return parsed
}

func calendarQuarterConfig() *spec.PeriodConfig {
	return &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{Type: fiscalCalendarQuarter},
		TimeBasis:      timeBasisCommit,
	}
}

// TestCadencePeriod_MatchesDocumentedFolderScheme pins the table in
// docs/configuration.md §Manual evidence folder scheme, which has
// promised a per-frequency {period_id} since before the code produced
// one. It also pins the contract with the Evidence SPA, whose
// currentPeriod() in src/lib/period.ts derives these same keys
// client-side: a customer who uploads where the SPA tells them must
// land in the folder the CLI reads.
//
// Scoped to the default calendar on purpose. The SPA reads only
// public/config.json, which carries no period block, so it can derive
// calendar-aligned keys and nothing else — under a fiscal_year or
// custom calendar the CLI's folders are correct and the SPA's upload
// hint is not, which is why docs/guides/manual-evidence.md tells those
// projects to take the path from `sigcomply evidence due`.
func TestCadencePeriod_MatchesDocumentedFolderScheme(t *testing.T) {
	cases := []struct {
		cadence string
		want    string
	}{
		{cadenceDaily, "2026-01-15"},
		{cadenceWeekly, "2026-W03"},
		{cadenceMonthly, period2026M1},
		{cadenceQuarterly, period2026Q1},
		{cadenceAnnual, period2026Y},
	}
	at := mustParse(t, tsJan15)
	for _, tc := range cases {
		t.Run(tc.cadence, func(t *testing.T) {
			p, err := planner.CadencePeriod(calendarQuarterConfig(), at, tc.cadence)
			if err != nil {
				t.Fatalf("CadencePeriod: %v", err)
			}
			if p.ID != tc.want {
				t.Errorf("ID = %q; want %q", p.ID, tc.want)
			}
		})
	}
}

func TestCadencePeriod_WindowsAndPriorIDs(t *testing.T) {
	cases := []struct {
		name      string
		cadence   string
		at        string
		wantID    string
		wantPrior string
		wantStart string
		wantEnd   string // first instant NOT in the period
	}{
		{
			name: "daily", cadence: cadenceDaily, at: tsJan15,
			wantID: "2026-01-15", wantPrior: "2026-01-14",
			wantStart: "2026-01-15T00:00:00Z", wantEnd: "2026-01-16T00:00:00Z",
		},
		{
			name: "weekly", cadence: cadenceWeekly, at: tsJan15,
			wantID: "2026-W03", wantPrior: "2026-W02",
			wantStart: "2026-01-12T00:00:00Z", wantEnd: "2026-01-19T00:00:00Z",
		},
		{
			name: "monthly", cadence: cadenceMonthly, at: tsJan15,
			wantID: period2026M1, wantPrior: "2025-12",
			wantStart: tsJan01Start, wantEnd: "2026-02-01T00:00:00Z",
		},
		{
			name: "quarterly", cadence: cadenceQuarterly, at: "2026-05-15T13:55:00Z",
			wantID: period2026Q2, wantPrior: period2026Q1,
			wantStart: tsApr01Start, wantEnd: "2026-07-01T00:00:00Z",
		},
		{
			name: "annual", cadence: cadenceAnnual, at: "2026-12-15T13:55:00Z",
			wantID: period2026Y, wantPrior: "2025",
			wantStart: tsJan01Start, wantEnd: "2027-01-01T00:00:00Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := planner.CadencePeriod(calendarQuarterConfig(), mustParse(t, tc.at), tc.cadence)
			if err != nil {
				t.Fatalf("CadencePeriod: %v", err)
			}
			if p.ID != tc.wantID {
				t.Errorf("ID = %q; want %q", p.ID, tc.wantID)
			}
			if p.PriorID != tc.wantPrior {
				t.Errorf("PriorID = %q; want %q", p.PriorID, tc.wantPrior)
			}
			if got, want := p.Start, mustParse(t, tc.wantStart); !got.Equal(want) {
				t.Errorf("Start = %s; want %s", got, want)
			}
			// End is the last representable instant of the period, so
			// the first instant of the next one must be after it.
			next := mustParse(t, tc.wantEnd)
			if !p.End.Before(next) {
				t.Errorf("End = %s; want before %s", p.End, next)
			}
			if next.Sub(p.End) != time.Nanosecond {
				t.Errorf("End = %s; want one nanosecond before %s", p.End, next)
			}
			if p.TimeBasis != timeBasisCommit {
				t.Errorf("TimeBasis = %q; want commit", p.TimeBasis)
			}
		})
	}
}

// The annual window is what makes an annual entry uploadable once a
// year: evidence filed in January must still satisfy a December run.
func TestCadencePeriod_AnnualWindowSpansTheWholeYear(t *testing.T) {
	december := mustParse(t, "2026-12-20T09:00:00Z")
	p, err := planner.CadencePeriod(calendarQuarterConfig(), december, cadenceAnnual)
	if err != nil {
		t.Fatalf("CadencePeriod: %v", err)
	}
	january := mustParse(t, "2026-01-09T10:00:00Z")
	if january.Before(p.Start) || january.After(p.End) {
		t.Errorf("January upload %s falls outside the annual window [%s, %s]", january, p.Start, p.End)
	}
}

func TestCadencePeriod_ISOWeekBoundaries(t *testing.T) {
	cases := []struct {
		at        string
		wantID    string
		wantStart string
	}{
		// 2026-01-01 is a Thursday, so the week that contains it is
		// ISO week 2026-W01 and it starts in the previous year.
		{"2026-01-01T12:00:00Z", period2026W1, tsDec29Start},
		{tsDec29Start, period2026W1, tsDec29Start},
		{"2026-01-04T23:59:59Z", period2026W1, tsDec29Start},
		{"2026-01-05T00:00:00Z", "2026-W02", "2026-01-05T00:00:00Z"},
		// 2026 is a 53-week ISO year.
		{"2026-12-31T00:00:00Z", "2026-W53", "2026-12-28T00:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.at, func(t *testing.T) {
			p, err := planner.CadencePeriod(calendarQuarterConfig(), mustParse(t, tc.at), cadenceWeekly)
			if err != nil {
				t.Fatalf("CadencePeriod: %v", err)
			}
			if p.ID != tc.wantID {
				t.Errorf("ID = %q; want %q", p.ID, tc.wantID)
			}
			if got, want := p.Start, mustParse(t, tc.wantStart); !got.Equal(want) {
				t.Errorf("Start = %s; want %s (weeks are Monday-anchored)", got, want)
			}
		})
	}
}

func TestCadencePeriod_YearAndQuarterBoundaries(t *testing.T) {
	cases := []struct {
		at      string
		cadence string
		wantID  string
	}{
		{tsJan01Start, cadenceAnnual, period2026Y},
		{tsDec31End, cadenceAnnual, period2026Y},
		{"2027-01-01T00:00:00Z", cadenceAnnual, "2027"},
		{tsMar31End, cadenceQuarterly, period2026Q1},
		{tsApr01Start, cadenceQuarterly, period2026Q2},
		{"2026-01-31T23:59:59Z", cadenceMonthly, period2026M1},
		{"2026-02-01T00:00:00Z", cadenceMonthly, "2026-02"},
	}
	for _, tc := range cases {
		t.Run(tc.at+"_"+tc.cadence, func(t *testing.T) {
			p, err := planner.CadencePeriod(calendarQuarterConfig(), mustParse(t, tc.at), tc.cadence)
			if err != nil {
				t.Fatalf("CadencePeriod: %v", err)
			}
			if p.ID != tc.wantID {
				t.Errorf("ID = %q; want %q", p.ID, tc.wantID)
			}
		})
	}
}

// A fiscal year is the project's declared annual window, so the annual
// cadence honors it. Shorter cadences have no fiscal definition in the
// config, so they stay calendar-aligned — and identical to the SPA's.
func TestCadencePeriod_FiscalYear(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{Type: fiscalYear, Starts: fiscalStartsApril},
		TimeBasis:      timeBasisCommit,
	}
	at := mustParse(t, "2026-05-15T13:55:00Z")

	annual, err := planner.CadencePeriod(cfg, at, cadenceAnnual)
	if err != nil {
		t.Fatalf("CadencePeriod(annual): %v", err)
	}
	if annual.ID != periodFY2026 {
		t.Errorf("annual ID = %q; want %q", annual.ID, periodFY2026)
	}
	if annual.PriorID != periodFY2025 {
		t.Errorf("annual PriorID = %q; want %q", annual.PriorID, periodFY2025)
	}

	quarterly, err := planner.CadencePeriod(cfg, at, cadenceQuarterly)
	if err != nil {
		t.Fatalf("CadencePeriod(quarterly): %v", err)
	}
	if quarterly.ID != period2026Q2 {
		t.Errorf("quarterly ID = %q; want %q", quarterly.ID, period2026Q2)
	}
}

// A custom calendar names its own windows; there is no way to subdivide
// them by cadence, so every cadence keeps the run's period.
func TestCadencePeriod_CustomCalendarKeepsRunPeriod(t *testing.T) {
	cfg := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{
			Type: fiscalCustom,
			Periods: []spec.CustomPeriod{
				{ID: period2026P01, Start: date2026Jan04, End: date2026Jan31},
				{ID: period2026P02, Start: date2026Feb01, End: date2026Feb28},
			},
		},
	}
	at := mustParse(t, "2026-02-10T00:00:00Z")
	for _, cadence := range []string{cadenceDaily, cadenceWeekly, cadenceMonthly, cadenceQuarterly, cadenceAnnual} {
		t.Run(cadence, func(t *testing.T) {
			p, err := planner.CadencePeriod(cfg, at, cadence)
			if err != nil {
				t.Fatalf("CadencePeriod: %v", err)
			}
			if p.ID != period2026P02 {
				t.Errorf("ID = %q; want the run period %q", p.ID, period2026P02)
			}
			if p.PriorID != period2026P01 {
				t.Errorf("PriorID = %q; want %q", p.PriorID, period2026P01)
			}
		})
	}
}

// continuous, hourly and every:<duration> name no calendar window. They
// keep the run's period rather than being rounded to one, so no cadence
// loses ground against today's behavior.
func TestCadencePeriod_UnalignedCadencesKeepRunPeriod(t *testing.T) {
	at := mustParse(t, "2026-05-15T13:55:00Z")
	for _, cadence := range []string{cadenceContinuous, "hourly", cadenceEvery6h, "on_push", ""} {
		name := cadence
		if name == "" {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			p, err := planner.CadencePeriod(calendarQuarterConfig(), at, cadence)
			if err != nil {
				t.Fatalf("CadencePeriod: %v", err)
			}
			if p.ID != period2026Q2 {
				t.Errorf("ID = %q; want the run period %q", p.ID, period2026Q2)
			}
		})
	}
}

// The SPA cannot mirror a fiscal or custom calendar, and we would
// rather the CLI be right than agree with a hint it cannot compute.
// This pins the divergence as deliberate rather than accidental.
func TestCadencePeriod_NonDefaultCalendarsDivergeFromTheSPAKeys(t *testing.T) {
	at := mustParse(t, "2026-05-15T13:55:00Z")
	const spaYearlyKey = period2026Y // what src/lib/period.ts emits for a yearly entry

	fiscal := &spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{Type: fiscalYear, Starts: fiscalStartsApril},
	}
	p, err := planner.CadencePeriod(fiscal, at, cadenceAnnual)
	if err != nil {
		t.Fatalf("CadencePeriod: %v", err)
	}
	if p.ID == spaYearlyKey {
		t.Errorf("annual ID = %q; a fiscal year must not collapse to the calendar year", p.ID)
	}
	if p.ID != periodFY2026 {
		t.Errorf("annual ID = %q; want %q", p.ID, periodFY2026)
	}
}

func TestCadencePeriod_UnknownCalendarErrors(t *testing.T) {
	cfg := &spec.PeriodConfig{FiscalCalendar: spec.FiscalCalendarConfig{Type: "lunar"}}
	if _, err := planner.CadencePeriod(cfg, mustParse(t, "2026-05-15T13:55:00Z"), cadenceAnnual); err == nil {
		t.Fatal("CadencePeriod: want an error for an unknown fiscal_calendar.type")
	}
}

// PeriodTime is the fix for period.time_basis, which the validator has
// always accepted and nothing has ever read.
func TestPeriodTime_HonorsTimeBasis(t *testing.T) {
	commit := mustParse(t, tsJan15)
	now := mustParse(t, "2026-07-02T09:00:00Z")
	cases := []struct {
		basis string
		want  time.Time
	}{
		{"", commit},
		{timeBasisCommit, commit},
		{timeBasisWallClock, now},
	}
	for _, tc := range cases {
		name := tc.basis
		if name == "" {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			got := planner.PeriodTime(&spec.PeriodConfig{TimeBasis: tc.basis}, commit, now)
			if !got.Equal(tc.want) {
				t.Errorf("PeriodTime = %s; want %s", got, tc.want)
			}
		})
	}
}

// A zero wall clock must not silently derive a year-1 period.
func TestPeriodTime_WallClockFallsBackWhenNowIsZero(t *testing.T) {
	commit := mustParse(t, tsJan15)
	got := planner.PeriodTime(&spec.PeriodConfig{TimeBasis: timeBasisWallClock}, commit, time.Time{})
	if !got.Equal(commit) {
		t.Errorf("PeriodTime = %s; want the commit time %s when now is zero", got, commit)
	}
}

func TestPeriodTime_NilConfigUsesCommit(t *testing.T) {
	commit := mustParse(t, tsJan15)
	now := mustParse(t, "2026-07-02T09:00:00Z")
	if got := planner.PeriodTime(nil, commit, now); !got.Equal(commit) {
		t.Errorf("PeriodTime = %s; want %s", got, commit)
	}
}

// The manual binding carries its own cadence-aligned window while the
// run's period stays whatever the fiscal calendar says. This is the
// whole point: a December run of an annual entry must read the folder
// the customer filled in January.
func TestPlan_ManualBindingCarriesCadencePeriod(t *testing.T) {
	cases := []struct {
		name        string
		cadence     string
		wantBinding string
		wantPrior   string
	}{
		{"annual", cadenceAnnual, period2026Y, "2025"},
		{"quarterly", cadenceQuarterly, period2026Q4, period2026Q3},
	}
	december := mustParse(t, "2026-12-20T09:00:00Z")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := core.Policy{
				ID:           "soc2.cc1.1.security_awareness_training",
				Controls:     []core.ControlRef{{ControlID: ctrlSOC2CC61}},
				EvidenceMode: core.EvidenceModeManual,
				CatalogEntry: "security_awareness_training",
				Cadence:      tc.cadence,
			}
			set := registry.NewSet()
			if err := set.Policies.Register(policy); err != nil {
				t.Fatalf("register policy: %v", err)
			}
			if err := set.Frameworks.Register(&fakeFramework{
				id: fwSOC2, version: "2017",
				policies: []core.PolicyRef{{PolicyID: policy.ID}},
			}); err != nil {
				t.Fatalf("register framework: %v", err)
			}
			plan, err := planner.Plan(&planner.Input{
				Config:     &spec.ProjectConfig{SchemaVersion: schemaProjectV1, Framework: fwSOC2},
				Registries: set,
				CommitTime: december,
				Now:        december,
			})
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			if plan.Period.ID != period2026Q4 {
				t.Errorf("run period = %q; want the run period to stay %q", plan.Period.ID, period2026Q4)
			}
			bindings := plan.Policies[0].Bindings[spec.ManualSlotName]
			if len(bindings) != 1 {
				t.Fatalf("manual bindings = %d; want 1", len(bindings))
			}
			got := bindings[0].Period
			if got == nil {
				t.Fatal("Binding.Period = nil; want the cadence-aligned window")
			}
			if got.ID != tc.wantBinding {
				t.Errorf("Binding.Period.ID = %q; want %q", got.ID, tc.wantBinding)
			}
			if got.PriorID != tc.wantPrior {
				t.Errorf("Binding.Period.PriorID = %q; want %q", got.PriorID, tc.wantPrior)
			}
		})
	}
}

// An automated binding has no manual folder, so it must not carry one —
// the collector keys the period override off exactly this.
func TestPlan_AutomatedBindingHasNoPeriod(t *testing.T) {
	set := setUp(t)
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: &spec.ProjectConfig{
			SchemaVersion: schemaProjectV1,
			Framework:     fwSOC2,
			Sources:       map[string]map[string]any{srcAWSIAMID: {}},
		},
		Registries: set,
		CommitTime: commit,
		Now:        commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, pp := range plan.Policies {
		for slot, bs := range pp.Bindings {
			for i := range bs {
				if bs[i].Period != nil {
					t.Errorf("policy %s slot %s binding %d: Period = %+v; want nil", pp.Spec.ID, slot, i, bs[i].Period)
				}
			}
		}
	}
}

// time_basis: wall_clock has been accepted by the validator and read by
// nothing. Under it the run's period follows the run clock, not HEAD.
func TestPlan_WallClockTimeBasisUsesTheRunClock(t *testing.T) {
	set := setUp(t)
	commit := mustParse(t, "2026-02-15T13:55:00Z")
	now := mustParse(t, "2026-07-02T09:00:00Z")
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1,
		Framework:     fwSOC2,
		Sources:       map[string]map[string]any{srcAWSIAMID: {}},
		Period:        spec.PeriodConfig{TimeBasis: timeBasisWallClock},
	}
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: now,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Period.ID != period2026Q3 {
		t.Errorf("Period.ID = %q; want 2026-Q3 (the run clock, not the commit's 2026-Q1)", plan.Period.ID)
	}
}
