package orchestrator

import (
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// emitVendorWarnings logs the non-fatal findings about
// experimental.vendors: unrecognized subkeys (tolerated — that tolerance
// is the point of the experimental: hatch — but a typo should still be
// loud) and configured sources the register does not claim. Everything
// fatal about the block has already failed the load.
func emitVendorWarnings(logger *log.Logger, cfg *spec.ProjectConfig) {
	for _, w := range planner.VendorWarnings(cfg) {
		logger.Warnf("vendors: %s", w)
	}
}
