package sources

import (
	"fmt"
	"os"
)

// ResolveToken resolves an API token for one source instance, in
// precedence order: an explicit `token` in config, then the environment
// variable named by `token_env`, then the shared fallback variable.
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
	return "", fmt.Errorf("%s: token required (set %s in config, or token_env naming an environment variable, or %s)", sourceID, configKey, fallbackEnv)
}
