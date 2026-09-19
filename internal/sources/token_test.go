package sources

import (
	"strings"
	"testing"
)

const testKeyTokenEnv = "token_env"

func TestResolveToken_ConfigWins(t *testing.T) {
	t.Setenv("FALLBACK_TOKEN", "from-env")
	got, err := ResolveToken(map[string]any{"token": "from-config"}, testSourceGitHub, "token", "FALLBACK_TOKEN")
	if err != nil || got != "from-config" {
		t.Fatalf("got (%q, %v); want from-config", got, err)
	}
}

// The point of token_env: two instances naming different variables
// authenticate as different principals.
func TestResolveToken_PerInstanceEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "shared")
	t.Setenv("GITHUB_TOKEN_LABS", "labs-only")

	shared, err := ResolveToken(map[string]any{}, testSourceGitHub, "token", "GITHUB_TOKEN")
	if err != nil || shared != "shared" {
		t.Fatalf("default instance got (%q, %v)", shared, err)
	}
	labs, err := ResolveToken(map[string]any{testKeyTokenEnv: "GITHUB_TOKEN_LABS"}, testSourceGitHub, "token", "GITHUB_TOKEN")
	if err != nil || labs != "labs-only" {
		t.Fatalf("labs instance got (%q, %v)", labs, err)
	}
}

// An empty token_env must fail, never silently fall through to the
// shared variable — that would authenticate one instance as another's
// identity and report success.
func TestResolveToken_EmptyTokenEnvDoesNotFallThrough(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "shared")
	_, err := ResolveToken(map[string]any{testKeyTokenEnv: "NOT_SET_ANYWHERE"}, testSourceGitHub, "token", "GITHUB_TOKEN")
	if err == nil {
		t.Fatal("want an error; a named-but-unset token_env must not borrow the shared token")
	}
	if !strings.Contains(err.Error(), "NOT_SET_ANYWHERE") {
		t.Errorf("error should name the variable: %v", err)
	}
}

func TestResolveToken_MissingListsEveryOption(t *testing.T) {
	_, err := ResolveToken(map[string]any{}, "okta", "api_token", "OKTA_API_TOKEN")
	if err == nil {
		t.Fatal("want an error when no credential is available")
	}
	for _, want := range []string{"api_token", testKeyTokenEnv, "OKTA_API_TOKEN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}
