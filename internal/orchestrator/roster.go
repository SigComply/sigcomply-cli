package orchestrator

import (
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// emitRosterWarnings logs the non-fatal findings about experimental.roster:
// unrecognized subkeys (tolerated — that tolerance is the point of the
// experimental: hatch — but a typo should still be loud) and a roster
// designated for a framework that never consults one. Everything fatal
// about the block has already failed the plan.
func emitRosterWarnings(logger *log.Logger, cfg *spec.ProjectConfig, set *registry.Set) {
	for _, w := range planner.RosterWarnings(cfg, set) {
		logger.Warnf("roster: %s", w)
	}
}
