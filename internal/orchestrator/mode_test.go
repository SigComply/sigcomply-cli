package orchestrator

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/collector"
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// testFramework is used as the framework ID in every mode-resolution
// test below. Kept as a file-local const so adding more tests
// doesn't trip goconst.
const testFramework = "soc2"

func newModeOptions(t *testing.T, mode Mode, filter *planner.Filter, v core.Vault) *Options {
	t.Helper()
	f := planner.Filter{}
	if filter != nil {
		f = *filter
	}
	return &Options{
		Config:     &spec.ProjectConfig{Framework: testFramework},
		Registries: registry.NewSet(),
		Mode:       mode,
		Filter:     f,
		Vault:      v,
		Stdout:     &bytes.Buffer{},
		Logger:     log.New(&bytes.Buffer{}, false),
		CommitTime: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
	}
}

func TestResolveMode_PRDefaultsToOnPushCadence(t *testing.T) {
	opts := newModeOptions(t, ModePR, &planner.Filter{}, newInMem())
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)

	filter, retry, rt := resolveMode(context.Background(), opts, now)
	if len(filter.Cadences) != 1 || filter.Cadences[0] != core.CadenceOnPush {
		t.Errorf("PR Cadences = %v; want [on_push]", filter.Cadences)
	}
	if retry.MaxAttempts != collector.RetryPR.MaxAttempts {
		t.Errorf("PR mode retry should use RetryPR (MaxAttempts=%d); got %d",
			collector.RetryPR.MaxAttempts, retry.MaxAttempts)
	}
	if rt.policyStates != nil {
		t.Error("PR mode must not load policy states")
	}
}

func TestResolveMode_PRRespectsExplicitFilter(t *testing.T) {
	// Power-user case: --pr --policies=foo,bar. The mode should NOT
	// override an explicit policy filter; the user is narrowing a PR
	// run to specific policies for diagnostic purposes.
	opts := newModeOptions(t, ModePR, &planner.Filter{Policies: []string{"p1", "p2"}}, newInMem())
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)

	filter, _, _ := resolveMode(context.Background(), opts, now)
	// Policy axis is preserved.
	if len(filter.Policies) != 2 {
		t.Errorf("Policies filter lost: %v", filter.Policies)
	}
	// Cadence axis is still defaulted because no cadence axis was set.
	if len(filter.Cadences) != 1 || filter.Cadences[0] != core.CadenceOnPush {
		t.Errorf("Cadences should default to [on_push] when no cadence axis was set; got %v", filter.Cadences)
	}
}

func TestResolveMode_ScheduledExplicitFilterSkipsStateLoad(t *testing.T) {
	// In scheduled mode, an explicit --policies forces every match to
	// evaluate — the state-load step is skipped because the planner
	// would just ignore states anyway (filter > cadence-gate).
	opts := newModeOptions(t, ModeScheduled,
		&planner.Filter{Policies: []string{"p1"}}, newInMem())
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)

	_, retry, rt := resolveMode(context.Background(), opts, now)
	if rt.policyStates != nil {
		t.Errorf("explicit filter should skip state load; got states len=%d", len(rt.policyStates))
	}
	if retry.MaxAttempts != collector.RetryScheduled.MaxAttempts {
		t.Errorf("Scheduled mode retry should use RetryScheduled; got MaxAttempts=%d", retry.MaxAttempts)
	}
}

func TestResolveMode_ManualUnchanged(t *testing.T) {
	opts := newModeOptions(t, ModeManual, &planner.Filter{Cadence: "daily"}, newInMem())
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)

	filter, retry, rt := resolveMode(context.Background(), opts, now)
	if filter.Cadence != "daily" {
		t.Errorf("manual mode must pass filter through unchanged; got %q", filter.Cadence)
	}
	if retry.MaxAttempts > 1 {
		t.Errorf("manual mode must use RetryNone; got MaxAttempts=%d", retry.MaxAttempts)
	}
	if rt.policyStates != nil {
		t.Error("manual mode must not load policy states")
	}
}
