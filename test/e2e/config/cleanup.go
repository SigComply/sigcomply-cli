//go:build e2e

package config

import (
	"os"
	"strings"
	"testing"
)

// ShouldCleanup determines whether cleanup should run for a scenario.
//
// Priority (highest to lowest):
//  1. E2E_SKIP_CLEANUP=true env var -> skip cleanup
//  2. Per-scenario cleanup: false in config.yaml
//  3. Global defaults.cleanup: false in config.yaml
//  4. Default: cleanup runs
func ShouldCleanup(cfg *E2EConfig, scenario *Scenario) bool {
	// 1. Env var override (highest priority)
	if v := os.Getenv("E2E_SKIP_CLEANUP"); strings.EqualFold(v, "true") || v == "1" {
		return false
	}

	// 2. Per-scenario override
	if scenario.Cleanup != nil {
		return *scenario.Cleanup
	}

	// 3. Global default
	if cfg.Defaults.Cleanup != nil {
		return *cfg.Defaults.Cleanup
	}

	// 4. Default: cleanup runs
	return true
}

// RegisterCleanup conditionally registers a cleanup function based on config.
// If cleanup is disabled, it logs the skip reason instead.
func RegisterCleanup(t *testing.T, cfg *E2EConfig, scenario *Scenario, cleanupFn func()) {
	t.Helper()

	if ShouldCleanup(cfg, scenario) {
		t.Cleanup(cleanupFn)
	} else {
		t.Log("Cleanup skipped (disabled by config or E2E_SKIP_CLEANUP)")
	}
}
