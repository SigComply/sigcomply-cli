//go:build e2e

// Package frameworks provides compliance framework resolution and result filtering for E2E tests.
package frameworks

import (
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// Resolve returns the engine.Framework for a given framework name.
func Resolve(name string) engine.Framework {
	switch name {
	case "soc2":
		return soc2.New()
	case "iso27001":
		return iso27001.New()
	default:
		return nil
	}
}

// FilterResults filters policy results by include/exclude lists.
// If include is non-empty, only results matching those policy IDs are kept.
// If exclude is non-empty, results matching those policy IDs are removed (applied after include).
// If both are empty/nil, all results are returned unchanged.
func FilterResults(results []evidence.PolicyResult, include, exclude []string) []evidence.PolicyResult {
	if len(include) == 0 && len(exclude) == 0 {
		return results
	}

	var filtered []evidence.PolicyResult

	if len(include) > 0 {
		includeSet := toSet(include)
		for _, r := range results {
			if includeSet[r.PolicyID] {
				filtered = append(filtered, r)
			}
		}
	} else {
		filtered = make([]evidence.PolicyResult, len(results))
		copy(filtered, results)
	}

	if len(exclude) > 0 {
		excludeSet := toSet(exclude)
		var final []evidence.PolicyResult
		for _, r := range filtered {
			if !excludeSet[r.PolicyID] {
				final = append(final, r)
			}
		}
		filtered = final
	}

	return filtered
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}
