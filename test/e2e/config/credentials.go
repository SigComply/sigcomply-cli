//go:build e2e

package config

import "testing"

// providerSDKEnvVars maps credential profile field names to standard SDK
// environment variables for each provider. When a scenario runs, the test
// runner reads the source env var from the profile (e.g. E2E_AWS_ACCESS_KEY_ID)
// and sets the standard SDK env var (e.g. AWS_ACCESS_KEY_ID) via t.Setenv.
//
// To add a new provider: add an entry here and a matching credential profile
// in e2e/config.yaml — no other Go code changes needed.
var providerSDKEnvVars = map[string]map[string]string{
	"aws": {
		"access_key_id":     "AWS_ACCESS_KEY_ID",
		"secret_access_key": "AWS_SECRET_ACCESS_KEY",
		"region":            "AWS_DEFAULT_REGION",
	},
	"github": {
		"token": "GITHUB_TOKEN",
	},
	"gitlab": {
		"token": "GITLAB_TOKEN",
	},
	"gcp": {
		"credentials_file": "GOOGLE_APPLICATION_CREDENTIALS",
		"project":          "GCP_PROJECT",
	},
	"azure": {
		"client_id":       "AZURE_CLIENT_ID",
		"client_secret":   "AZURE_CLIENT_SECRET",
		"tenant_id":       "AZURE_TENANT_ID",
		"subscription_id": "AZURE_SUBSCRIPTION_ID",
	},
}

// ApplyCredentials sets the standard SDK environment variables for a provider
// using t.Setenv (automatically restored after the test completes).
// This allows each scenario to run with its own credentials without
// cross-contamination — no t.Parallel() needed.
func ApplyCredentials(t *testing.T, creds *ResolvedCredentials) {
	t.Helper()

	mapping, ok := providerSDKEnvVars[creds.Provider]
	if !ok {
		t.Fatalf("No SDK env var mapping for provider %q — add it to providerSDKEnvVars in credentials.go", creds.Provider)
	}

	for key, value := range creds.Values {
		sdkEnvVar, ok := mapping[key]
		if !ok {
			// Extra fields (e.g. "org" for GitHub) don't map to SDK env vars.
			// They're still available via creds.Values for direct use.
			continue
		}
		t.Setenv(sdkEnvVar, value)
	}
}
