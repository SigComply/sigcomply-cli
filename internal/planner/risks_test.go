package planner

import (
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

func riskCfg(t *testing.T, register []any, extra map[string]any) *spec.ProjectConfig {
	t.Helper()
	block := map[string]any{"register": register}
	for k, v := range extra {
		block[k] = v
	}
	return &spec.ProjectConfig{
		Framework:    riskFramework,
		Experimental: map[string]any{spec.RisksKey: block},
	}
}

func riskEntry(id string, controls []any, assessedAt string) any {
	return map[string]any{
		"id": id, "description": "A risk.", "owner": "ciso@example.com",
		"level": "high", "treatment": "modify", "controls": controls,
		"residual_level": "low", "assessed_at": assessedAt,
	}
}

const (
	riskCtrlA81   = "A.8.1"
	riskFramework = "iso27001"
)

var riskCatalog = []core.Control{{ID: riskCtrlA81}, {ID: "A.8.24"}}

const riskPeriodStart = "2026-01-01"

func periodStart(t *testing.T) time.Time {
	t.Helper()
	ts, err := time.Parse("2006-01-02", riskPeriodStart)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestRiskWarnings_SilentWithoutRegister(t *testing.T) {
	if got := RiskWarnings(&spec.ProjectConfig{}, riskCatalog, periodStart(t)); got != nil {
		t.Errorf("warnings = %v; want none when no register is declared", got)
	}
}

func TestRiskWarnings_CleanRegisterIsSilent(t *testing.T) {
	cfg := riskCfg(t, []any{riskEntry("r-001", []any{riskCtrlA81}, "2025-06-01")}, nil)
	if got := RiskWarnings(cfg, riskCatalog, periodStart(t)); got != nil {
		t.Errorf("warnings = %v; want none", got)
	}
}

// A control-ID typo would otherwise just fail to join, silently — the
// SoA row would render with no risk beside it and nothing would say the
// operator meant otherwise.
func TestRiskWarnings_NamesUnknownControl(t *testing.T) {
	cfg := riskCfg(t, []any{
		riskEntry("r-001", []any{"A.8.07"}, "2025-06-01"),
		riskEntry("r-002", []any{riskCtrlA81}, "2025-06-01"),
	}, nil)
	got := strings.Join(RiskWarnings(cfg, riskCatalog, periodStart(t)), "\n")

	if !strings.Contains(got, `name control "A.8.07"`) || !strings.Contains(got, "r-001") {
		t.Errorf("warnings = %q; want the unknown control named with its risk", got)
	}
	if strings.Contains(got, riskCtrlA81+"\"") {
		t.Errorf("warnings = %q; must not warn about a control the framework does define", got)
	}
}

// Without a catalog, "unknown" is unknowable — warning would fire on
// every control of every run.
func TestRiskWarnings_NoCatalogSkipsControlCheck(t *testing.T) {
	cfg := riskCfg(t, []any{riskEntry("r-001", []any{"A.8.07"}, "2025-06-01")}, nil)
	if got := RiskWarnings(cfg, nil, periodStart(t)); got != nil {
		t.Errorf("warnings = %v; want none without a control catalog", got)
	}
}

func TestRiskWarnings_StaleAssessment(t *testing.T) {
	cases := []struct {
		name       string
		assessedAt string
		wantStale  bool
	}{
		// An honest annual cycle must not warn in the weeks between the
		// anniversary and the review actually happening.
		{"assessed last year", "2025-06-01", false},
		{"just inside the window", "2024-08-01", false},
		{"three years old", "2023-01-01", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := riskCfg(t, []any{riskEntry("r-001", []any{riskCtrlA81}, tc.assessedAt)}, nil)
			got := strings.Join(RiskWarnings(cfg, riskCatalog, periodStart(t)), "\n")
			if stale := strings.Contains(got, "have not been reassessed"); stale != tc.wantStale {
				t.Errorf("assessed_at %s: stale = %v, want %v (warnings: %q)", tc.assessedAt, stale, tc.wantStale, got)
			}
		})
	}
}

func TestRiskWarnings_ZeroPeriodStartSkipsStaleCheck(t *testing.T) {
	cfg := riskCfg(t, []any{riskEntry("r-001", []any{riskCtrlA81}, "2001-01-01")}, nil)
	if got := RiskWarnings(cfg, riskCatalog, time.Time{}); got != nil {
		t.Errorf("warnings = %v; want none with no period to compare against", got)
	}
}

func TestRiskWarnings_ReportsUnknownSubkey(t *testing.T) {
	cfg := riskCfg(t, []any{riskEntry("r-001", []any{riskCtrlA81}, "2025-06-01")},
		map[string]any{"reviewed_every": "12m"})
	got := strings.Join(RiskWarnings(cfg, riskCatalog, periodStart(t)), "\n")
	if !strings.Contains(got, "ignoring unrecognized key experimental.risks.reviewed_every") {
		t.Errorf("warnings = %q; want the unknown subkey reported", got)
	}
}
