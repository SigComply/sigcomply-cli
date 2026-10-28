package orchestrator

import (
	"os"
	"testing"
)

// TestMain clears the CI variables that mark a pull-request pipeline, so
// tests that expect a run to advance cadence state pass when the suite
// itself runs in one.
func TestMain(m *testing.M) {
	for _, k := range []string{envGitHubEventName, envMergeRequestIID} {
		_ = os.Unsetenv(k) //nolint:errcheck // best effort; tests that care set their own value
	}
	os.Exit(m.Run())
}
