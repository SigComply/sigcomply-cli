package orchestrator

import (
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// emitRiskWarnings logs the non-fatal findings about experimental.risks:
// unrecognized subkeys, risks naming a control this framework does not
// define, and risks nobody has reassessed inside the review window.
// Everything fatal about the block has already failed the load.
//
// The period start comes from the plan rather than the wall clock, for
// the same reason every other date comparison in a run does: the audit
// window is frozen at plan time from the commit's timestamp, so a
// re-run of an old commit reports what was true then.
func emitRiskWarnings(logger *log.Logger, cfg *spec.ProjectConfig, regs *registry.Set, plan *planner.RunPlan) {
	if logger == nil || cfg == nil {
		return
	}
	var periodStart time.Time
	if plan != nil {
		periodStart = plan.Period.Start
	}
	for _, w := range planner.RiskWarnings(cfg, frameworkControls(cfg.Framework, regs), periodStart) {
		logger.Warnf("risks: %s", w)
	}
}

// frameworkControls returns the framework's control catalog, or nil when
// it is not registered — in which case the unknown-control check is
// skipped rather than guessed at.
func frameworkControls(framework string, regs *registry.Set) []core.Control {
	if regs == nil || regs.Frameworks == nil {
		return nil
	}
	fw, ok := regs.Frameworks.Lookup(framework)
	if !ok {
		return nil
	}
	return fw.Controls()
}
