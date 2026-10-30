package orchestrator

import (
	"testing"
	"time"
)

// statePath is PolicyStatePath under the test framework, for tests
// whose policy IDs are known good.
func statePath(policyID string) string {
	p, err := PolicyStatePath(testFramework, policyID)
	if err != nil {
		panic(err)
	}
	return p
}

// TestVaultKeyBuilders_RejectUnsafeSegments feeds a path-escaping value
// to every argument of the orchestrator's vault-key builders. A policy
// ID or period ID with "/" or ".." would otherwise put results, the
// manifest or a state shard outside their folder on S3, GCS and Azure.
func TestVaultKeyBuilders_RejectUnsafeSegments(t *testing.T) {
	const bad = "../../escape"
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	builders := map[string]func() error{
		"run root framework": func() error { _, err := buildRunRoot(bad, "2026-Q1", now, "abcd1234"); return err },
		"run root period":    func() error { _, err := buildRunRoot("soc2", bad, now, "abcd1234"); return err },
		"run root run id":    func() error { _, err := buildRunRoot("soc2", "2026-Q1", now, "a/b"); return err },
		"state framework":    func() error { _, err := PolicyStatePath(bad, "p1"); return err },
		"state policy":       func() error { _, err := PolicyStatePath("soc2", bad); return err },
		"state prefix":       func() error { _, err := PolicyStatePrefix(bad); return err },
		"result runRoot":     func() error { _, err := runFilePath(bad, "summary.json"); return err },
		"result policy":      func() error { _, err := policyResultPath("soc2/2026-Q1/run_x", bad); return err },
	}
	for name, build := range builders {
		if build() == nil {
			t.Errorf("%s: unsafe segment accepted", name)
		}
	}
	if got, err := buildRunRoot("soc2", "2026-Q1", now, "abcd1234-ef"); err != nil || got != "soc2/2026-Q1/run_20261030T000000Z_abcd1234" {
		t.Errorf("buildRunRoot = %q, %v", got, err)
	}
}
