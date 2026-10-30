package orchestrator

import (
	"os"
	"testing"
)

// pullRequestEnvVars lists the variables InPullRequestPipeline reads.
var pullRequestEnvVars = []string{envGitHubEventName, envMergeRequestIID, envExternalPullRequestIID}

// TestMain clears the CI variables that mark a pull-request pipeline, so
// tests that expect a run to advance cadence state pass when the suite
// itself runs in one.
func TestMain(m *testing.M) {
	for _, k := range pullRequestEnvVars {
		_ = os.Unsetenv(k) //nolint:errcheck // best effort; tests that care set their own value
	}
	os.Exit(m.Run())
}
