package orchestrator

import (
	"sort"

	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/scope"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// emitUnboundSourceWarnings names configured sources no policy slot
// accepts anything from, so they were never consulted.
//
// The collection banner prints before planning — deliberately, so the
// operator sees what will be reached before any API call — which means
// it cannot know which sources the plan actually bound. Listed and
// unbound therefore reads as active: an active_directory source with no
// experimental.roster is announced and then silently ignored. This says
// so after the plan exists, in the same non-fatal register as the
// roster and coverage-skew warnings.
//
// Non-fatal by design: an unused source is a config smell, not an
// error. experimental.scope is where an operator turns "this source
// must be reached" into a verdict.
func emitUnboundSourceWarnings(logger *log.Logger, cfg *spec.ProjectConfig, plan *planner.RunPlan) {
	if logger == nil || cfg == nil || len(cfg.Sources) == 0 {
		return
	}
	bound := scope.BoundSources(plan)

	unused := make([]string, 0, len(cfg.Sources))
	for id := range cfg.Sources {
		if _, ok := bound[id]; !ok {
			unused = append(unused, id)
		}
	}
	sort.Strings(unused)

	for _, id := range unused {
		logger.Warnf("unbound-source: %s is configured but no policy slot accepts what it emits, so it was never consulted", id)
	}
}
