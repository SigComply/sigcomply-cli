package planner

import (
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// experimentalKeys are the experimental: features this CLI reads.
var experimentalKeys = []string{spec.ScopeKey, spec.VendorsKey, spec.RisksKey, spec.RosterKey}

// ExperimentalKeyWarnings reports keys directly under experimental: that
// no feature reads. A misspelled `scopee:` silently turns off the
// SCOPE INCOMPLETE gate, and `vendor:` silently drops the vendor
// fan-out, with nothing in the output to say so.
//
// Warning, never error, for the reason experimental: exists: a newer
// config may carry a key this CLI predates, and that must not fail the
// run.
func ExperimentalKeyWarnings(cfg *spec.ProjectConfig) []string {
	if cfg == nil {
		return nil
	}
	known := make(map[string]struct{}, len(experimentalKeys))
	for _, k := range experimentalKeys {
		known[k] = struct{}{}
	}
	var out []string
	for _, k := range sortedKeys(cfg.Experimental) {
		if _, ok := known[k]; !ok {
			out = append(out, fmt.Sprintf("experimental: unrecognized key %q, so it was ignored; this CLI reads %v", k, experimentalKeys))
		}
	}
	return out
}
