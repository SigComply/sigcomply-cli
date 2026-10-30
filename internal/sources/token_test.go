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
	// The environment variable is the recommended route and leads; a
	// literal token in a committed file is the last resort.
	if strings.Index(err.Error(), "OKTA_API_TOKEN") > strings.Index(err.Error(), "api_token in the config") {
		t.Errorf("error should lead with the environment variable: %v", err)
	}
}

// token_env must never point a source at a CI or cloud credential: the
// source would send that secret to whatever host its config names.
func TestResolveToken_RefusesCredentialVariables(t *testing.T) {
	for _, name := range []string{
		"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "aws_secret_access_key",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_RUNTIME_TOKEN",
		"CI_JOB_TOKEN", "CI_JOB_JWT_V2", "CI_REGISTRY_PASSWORD",
		"SIGCOMPLY_ID_TOKEN", "AWS_ID_TOKEN", "VAULT_ID_TOKEN",
		"GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN",
		"AZURE_CLIENT_SECRET", "AZURE_FEDERATED_TOKEN_FILE",
		"CI_REPOSITORY_URL", "ARM_CLIENT_SECRET", "ARM_OIDC_TOKEN", "VAULT_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN",
		"SIGCOMPLY_OIDC_TOKEN", "DEPLOY_OIDC", "MY_JWT", "VAULT_JWT_TOKEN",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "a-secret-value")
			got, err := ResolveToken(map[string]any{testKeyTokenEnv: name}, testSourceGitHub, "token", "GITHUB_TOKEN")
			if err == nil {
				t.Fatalf("token_env %s was accepted (got %q)", name, got)
			}
			if !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), "a-secret-value") {
				t.Errorf("error should name the variable and never its value: %v", err)
			}
		})
	}
}

// The documented per-source variables, and names derived from them, stay
// usable through token_env.
func TestResolveToken_AllowsSourceTokenVariables(t *testing.T) {
	for _, name := range []string{"GITHUB_TOKEN", "GITHUB_TOKEN_LABS", "GITLAB_TOKEN", "OKTA_API_TOKEN", "SIGCOMPLY_AD_BIND_PASSWORD", "CI_GITHUB_PAT"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "tok")
			got, err := ResolveToken(map[string]any{testKeyTokenEnv: name}, testSourceGitHub, "token", "GITHUB_TOKEN")
			if err != nil || got != "tok" {
				t.Fatalf("got (%q, %v); want tok", got, err)
			}
		})
	}
}

func TestResolveEndpoint(t *testing.T) {
	got, err := ResolveEndpoint(map[string]any{}, testSourceGitHub, "base_url")
	if err != nil || got != "" {
		t.Fatalf("unset key: got (%q, %v); want empty and no error", got, err)
	}
	got, err = ResolveEndpoint(map[string]any{"base_url": "https://ghe.example.com/api/v3"}, testSourceGitHub, "base_url")
	if err != nil || got != "https://ghe.example.com/api/v3" {
		t.Fatalf("https: got (%q, %v)", got, err)
	}
	_, err = ResolveEndpoint(map[string]any{"base_url": "http://ghe.example.com"}, testSourceGitHub, "base_url")
	if err == nil || !strings.Contains(err.Error(), "base_url") || !strings.Contains(err.Error(), testSourceGitHub) {
		t.Fatalf("http: want an error naming the source and key; got %v", err)
	}
}
