package sourcetest

import (
	"os"
	"strings"
	"testing"
)

// Live tests (L4a in the testing strategy) hit a real SaaS/cloud API to detect
// drift that cassettes can't. They carry the `//go:build live` build tag, so the
// default `go test ./...` (and therefore the coverage gate and CI's unit job)
// never compiles them — run them explicitly with `make test-live` /
// `go test -tags live ./...`. Each live test calls RequireEnv first so it
// no-ops cleanly when its credentials are absent (the common case: PRs,
// contributors, the scheduled job for a provider whose secret isn't configured).

// lookupEnv partitions keys into the set that is present (non-empty) and the
// ordered list that is missing. Pure, so the gating logic is unit-testable.
func lookupEnv(keys []string) (vals map[string]string, missing []string) {
	vals = make(map[string]string, len(keys))
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			vals[k] = v
		} else {
			missing = append(missing, k)
		}
	}
	return vals, missing
}

// RequireEnv skips the test unless every named environment variable is set
// (non-empty), returning their values keyed by name. Use it as the first line of
// a //go:build live test so it no-ops when its credentials aren't configured:
//
//	env := sourcetest.RequireEnv(t, "GITHUB_TEST_TOKEN", "GITHUB_TEST_ORG")
//	// ... use env["GITHUB_TEST_TOKEN"] ...
func RequireEnv(t *testing.T, keys ...string) map[string]string {
	t.Helper()
	vals, missing := lookupEnv(keys)
	if len(missing) > 0 {
		t.Skipf("live test: requires env %s — skipping", strings.Join(missing, ", "))
	}
	return vals
}
