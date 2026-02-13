//go:build e2e

package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	// Blank import to trigger collector init() registration.
	_ "github.com/sigcomply/sigcomply-cli/test/e2e/collectors"

	"github.com/sigcomply/sigcomply-cli/test/e2e/config"
	"github.com/sigcomply/sigcomply-cli/test/e2e/pipeline"
)

// TestE2EFullFlow runs the full compliance pipeline for each enabled scenario:
// collect -> evaluate -> hash -> sign -> store -> verify.
//
// Scenarios run sequentially (not parallel) because each may use different
// credentials via t.Setenv. Scenarios whose credential env vars are missing
// are skipped, not failed — safe for local dev.
func TestE2EFullFlow(t *testing.T) {
	cfg, err := config.LoadConfig()
	require.NoError(t, err, "Failed to load E2E config")

	scenarios := cfg.EnabledScenarios()
	require.NotEmpty(t, scenarios, "No enabled E2E scenarios found")

	for _, scenario := range scenarios {
		scenario := scenario // capture loop variable
		t.Run(scenario.Name, func(t *testing.T) {
			// Resolve all credential profiles — skip scenario if any env vars missing
			var allCreds []*config.ResolvedCredentials
			for _, profileName := range scenario.Credentials {
				creds, err := cfg.ResolveCredentials(profileName)
				if err != nil {
					t.Skipf("Skipping %s: %v", scenario.Name, err)
				}
				allCreds = append(allCreds, creds)
			}
			require.NotEmpty(t, allCreds, "Scenario %s has no credential profiles", scenario.Name)

			// Set standard SDK env vars for all providers in this scenario.
			// t.Setenv restores original values after the subtest completes.
			for _, creds := range allCreds {
				config.ApplyCredentials(t, creds)
			}

			pipeline.RunScenario(t, cfg, allCreds, &scenario)
		})
	}
}
