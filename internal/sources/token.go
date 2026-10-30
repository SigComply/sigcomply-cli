package sources

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/endpoint"
)

// ErrNoToken is wrapped by ResolveToken's error when no credential is
// configured at all, so a caller can word that case its own way.
var ErrNoToken = errors.New("token required")

// ResolveToken resolves an API token for one source instance, in
// precedence order: an explicit `token` in config, then the environment
// variable named by `token_env`, then the shared fallback variable. It is
// the only place a source reads a credential from the environment
// (forbidigo bans os.Getenv elsewhere in internal/sources), and it
// refuses a token_env that names a CI or cloud credential.
//
// `token_env` exists for multi-instance configs. The shared fallback
// (GITHUB_TOKEN, GITLAB_TOKEN, OKTA_API_TOKEN) is process-global, so two
// instances that both rely on it authenticate as the same principal and
// collect the same org twice under two different names — evidence that
// looks independent and is not. Naming a different variable per instance
// is what keeps their credentials distinct without putting secrets in a
// file that lives in git.
//
//	sources:
//	  github:
//	    org: acme
//	  "github[labs]":
//	    org: acme-labs
//	    token_env: GITHUB_TOKEN_LABS
//
// configKey/fallbackEnv name the plugin's own keys so the error message
// can list every way to supply the credential.
func ResolveToken(cfg map[string]any, sourceID, configKey, fallbackEnv string) (string, error) {
	if tok := StringOpt(cfg, configKey); tok != "" {
		return tok, nil
	}
	if name := StringOpt(cfg, "token_env"); name != "" {
		if deniedTokenEnv(name) {
			return "", fmt.Errorf("%s: token_env names %s, a CI or cloud credential variable, which a source never reads: "+
				"store the source's token in a variable of its own and name that", sourceID, name)
		}
		tok := os.Getenv(name)
		if tok == "" {
			// Silently falling through to the shared variable here would
			// be the worst outcome: the instance would authenticate as
			// some other instance's identity and report success.
			return "", fmt.Errorf("%s: token_env names %s, which is empty or unset", sourceID, name)
		}
		return tok, nil
	}
	if tok := os.Getenv(fallbackEnv); tok != "" {
		return tok, nil
	}
	// The environment comes first in the message: a secret in
	// .sigcomply.yaml ends up in git, and in CI the variable must be
	// passed to the step explicitly (GitHub Actions exports no
	// GITHUB_TOKEN to steps on its own).
	return "", fmt.Errorf("%s: %w: export %s, or set token_env to the name of the variable that holds it "+
		"(in CI, pass it to the step from a secret or masked variable). %s in the config also works but puts the secret in the repository",
		sourceID, ErrNoToken, fallbackEnv, configKey)
}

// ResolveEndpoint reads the URL a source sends its credential to (a
// GitHub Enterprise or self-managed GitLab base_url, an S3-compatible
// endpoint) and refuses one that is not https (http to localhost is
// allowed for tests). An unset key returns "": the source's default host.
// Every such key goes through here, so the rule cannot be skipped for one
// source; a registry-wide test in internal/sources/builtin checks it.
func ResolveEndpoint(cfg map[string]any, sourceID, key string) (string, error) {
	raw := StringOpt(cfg, key)
	if raw == "" {
		return "", nil
	}
	if err := endpoint.ValidateHTTPS(fmt.Sprintf("%s: %q", sourceID, key), raw); err != nil {
		return "", err
	}
	return raw, nil
}

// deniedTokenEnvPrefixes and deniedTokenEnvMarkers name the variables
// token_env may not read: CI and cloud credentials the runner or the
// job's own setup put in the environment. A source sends its token to
// the host its config names, so `token_env: AWS_SECRET_ACCESS_KEY` with
// a base_url someone controls would hand them the job's credentials.
// Matching is case-insensitive (Windows env names are).
var (
	deniedTokenEnvPrefixes = []string{"AWS_", "ACTIONS_", "GOOGLE_", "AZURE_", "ARM_", "CLOUDSDK_", "CI_JOB_"}
	deniedTokenEnvMarkers  = []string{"ID_TOKEN"}
	// CI_REPOSITORY_URL embeds the GitLab job token in its userinfo.
	deniedTokenEnvExact = []string{"CI_REGISTRY_PASSWORD", "CI_DEPLOY_PASSWORD", "CI_DEPENDENCY_PROXY_PASSWORD",
		"CI_REPOSITORY_URL", "VAULT_TOKEN"}
)

// deniedTokenEnv reports whether token_env may not read name.
func deniedTokenEnv(name string) bool {
	upper := strings.ToUpper(name)
	for _, p := range deniedTokenEnvPrefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	for _, m := range deniedTokenEnvMarkers {
		if strings.Contains(upper, m) {
			return true
		}
	}
	return slices.Contains(deniedTokenEnvExact, upper)
}
