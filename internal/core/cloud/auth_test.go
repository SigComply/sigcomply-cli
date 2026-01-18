package cloud

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tracevault/tracevault-cli/internal/core/attestation"
)

// Test helper functions for env var management
func setEnv(key, value string) {
	_ = os.Setenv(key, value) //nolint:errcheck // Test helper, error not critical
}

func unsetEnv(key string) {
	_ = os.Unsetenv(key) //nolint:errcheck // Test helper, error not critical
}

func TestDetectAuth_NoAuth(t *testing.T) {
	// Save and restore environment
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	originalGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
		if originalGHURL != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGHURL)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
		if originalGLJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalGLJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	// Clear all auth sources
	unsetEnv("TRACEVAULT_API_TOKEN")
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	unsetEnv("CI_JOB_JWT_V2")

	ctx := context.Background()
	result, err := DetectAuth(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodNone, result.Method)
	assert.Empty(t, result.Token)
}

func TestDetectAuth_APIToken(t *testing.T) {
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
	})

	setEnv("TRACEVAULT_API_TOKEN", "test-api-token")

	ctx := context.Background()
	result, err := DetectAuth(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodAPIToken, result.Method)
	assert.Equal(t, "test-api-token", result.Token)
}

func TestDetectAuth_ConfigAPIToken(t *testing.T) {
	// Ensure no env token
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
	})
	unsetEnv("TRACEVAULT_API_TOKEN")

	ctx := context.Background()
	cfg := &AuthConfig{
		APIToken: "config-api-token",
	}
	result, err := DetectAuth(ctx, cfg)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodAPIToken, result.Method)
	assert.Equal(t, "config-api-token", result.Token)
}

func TestDetectAuth_APITokenPrecedence(t *testing.T) {
	// When both API token and OIDC are available, API token takes precedence by default
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
		if originalGLJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalGLJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	setEnv("TRACEVAULT_API_TOKEN", "api-token")
	setEnv("CI_JOB_JWT_V2", "gitlab-jwt")

	ctx := context.Background()
	result, err := DetectAuth(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodAPIToken, result.Method)
	assert.Equal(t, "api-token", result.Token)
}

func TestDetectAuth_PreferOIDC(t *testing.T) {
	// When PreferOIDC is set, OIDC takes precedence over API token
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
		if originalGLJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalGLJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	setEnv("TRACEVAULT_API_TOKEN", "api-token")
	setEnv("CI_JOB_JWT_V2", "gitlab-jwt")

	ctx := context.Background()
	cfg := &AuthConfig{
		PreferOIDC: true,
	}
	result, err := DetectAuth(ctx, cfg)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodOIDC, result.Method)
	assert.Equal(t, "gitlab-jwt", result.Token)
	assert.Equal(t, attestation.ProviderGitLabCI, result.OIDCProvider)
}

func TestDetectAuth_GitLabCI(t *testing.T) {
	// Clear API token and GitHub Actions
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	originalGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
		if originalGHURL != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGHURL)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
		if originalGLJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalGLJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	unsetEnv("TRACEVAULT_API_TOKEN")
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	setEnv("CI_JOB_JWT_V2", "gitlab-jwt-token")

	ctx := context.Background()
	result, err := DetectAuth(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodOIDC, result.Method)
	assert.Equal(t, "gitlab-jwt-token", result.Token)
	assert.Equal(t, attestation.ProviderGitLabCI, result.OIDCProvider)
}

func TestConfigureClientAuth_NoAuth(t *testing.T) {
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	originalGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
		if originalGHURL != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGHURL)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
		if originalGLJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalGLJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	unsetEnv("TRACEVAULT_API_TOKEN")
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	unsetEnv("CI_JOB_JWT_V2")

	ctx := context.Background()
	client := NewClient(nil)
	err := ConfigureClientAuth(ctx, client, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authentication available")
}

func TestConfigureClientAuth_WithAPIToken(t *testing.T) {
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
	})

	setEnv("TRACEVAULT_API_TOKEN", "test-api-token")

	ctx := context.Background()
	client := NewClient(nil)
	err := ConfigureClientAuth(ctx, client, nil)

	require.NoError(t, err)
	assert.True(t, client.IsConfigured())
	assert.Equal(t, "test-api-token", client.config.APIToken)
}

func TestNewAuthenticatedClient_Success(t *testing.T) {
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
	})

	setEnv("TRACEVAULT_API_TOKEN", "test-api-token")

	ctx := context.Background()
	client, err := NewAuthenticatedClient(ctx, nil)

	require.NoError(t, err)
	require.NotNil(t, client)
	assert.True(t, client.IsConfigured())
}

func TestNewAuthenticatedClient_NoAuth(t *testing.T) {
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	originalGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
		if originalGHURL != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGHURL)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
		if originalGLJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalGLJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	unsetEnv("TRACEVAULT_API_TOKEN")
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	unsetEnv("CI_JOB_JWT_V2")

	ctx := context.Background()
	client, err := NewAuthenticatedClient(ctx, nil)

	require.Error(t, err)
	assert.Nil(t, client)
}

func TestMustNewAuthenticatedClient_ReturnsUnconfiguredOnError(t *testing.T) {
	originalAPIToken := os.Getenv("TRACEVAULT_API_TOKEN")
	originalGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalAPIToken != "" {
			setEnv("TRACEVAULT_API_TOKEN", originalAPIToken)
		} else {
			unsetEnv("TRACEVAULT_API_TOKEN")
		}
		if originalGHURL != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGHURL)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
		if originalGLJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalGLJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	unsetEnv("TRACEVAULT_API_TOKEN")
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	unsetEnv("CI_JOB_JWT_V2")

	ctx := context.Background()
	client := MustNewAuthenticatedClient(ctx, nil)

	require.NotNil(t, client)
	assert.False(t, client.IsConfigured())
}

func TestIsOIDCAvailable(t *testing.T) {
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	originalGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	t.Cleanup(func() {
		if originalGLJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalGLJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
		if originalGHURL != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGHURL)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
	})

	// Not available when no OIDC env vars
	unsetEnv("CI_JOB_JWT_V2")
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	assert.False(t, IsOIDCAvailable())

	// Available when GitLab CI
	setEnv("CI_JOB_JWT_V2", "token")
	assert.True(t, IsOIDCAvailable())
}

func TestGetOIDCProvider(t *testing.T) {
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	originalGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	t.Cleanup(func() {
		if originalGLJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalGLJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
		if originalGHURL != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGHURL)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
	})

	unsetEnv("CI_JOB_JWT_V2")
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	assert.Equal(t, attestation.ProviderUnknown, GetOIDCProvider())

	setEnv("CI_JOB_JWT_V2", "token")
	assert.Equal(t, attestation.ProviderGitLabCI, GetOIDCProvider())
}

func TestTokenInfoFromOIDC(t *testing.T) {
	// Test nil input
	assert.Nil(t, TokenInfoFromOIDC(nil))

	// Test with token
	oidcToken := &attestation.OIDCToken{
		Token:    "test-token",
		Provider: attestation.ProviderGitHubActions,
		Subject:  "repo:owner/repo:ref:refs/heads/main",
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: "https://api.tracevault.io",
	}

	tokenInfo := TokenInfoFromOIDC(oidcToken)
	require.NotNil(t, tokenInfo)
	assert.Equal(t, "test-token", tokenInfo.Token)
	assert.Equal(t, "github-actions", tokenInfo.Provider)
	assert.Equal(t, "repo:owner/repo:ref:refs/heads/main", tokenInfo.Subject)
	assert.Equal(t, "https://token.actions.githubusercontent.com", tokenInfo.Issuer)
	assert.Equal(t, "https://api.tracevault.io", tokenInfo.Audience)
}

func TestRefreshableAuth_NeedsRefresh(t *testing.T) {
	client := NewClient(nil)
	auth := NewRefreshableAuth(client, nil)

	// Needs refresh when result is nil
	assert.True(t, auth.NeedsRefresh())

	// Set a result
	auth.result = &AuthResult{
		Method: AuthMethodAPIToken,
		Token:  "token",
	}
	// API token doesn't need refresh
	assert.False(t, auth.NeedsRefresh())
}

func TestRefreshableAuth_Method(t *testing.T) {
	client := NewClient(nil)
	auth := NewRefreshableAuth(client, nil)

	// Default method is none
	assert.Equal(t, AuthMethodNone, auth.Method())

	// Set a result
	auth.result = &AuthResult{
		Method: AuthMethodOIDC,
	}
	assert.Equal(t, AuthMethodOIDC, auth.Method())
}

func TestAuthMethodConstants(t *testing.T) {
	assert.Equal(t, AuthMethod("none"), AuthMethodNone)
	assert.Equal(t, AuthMethod("api-token"), AuthMethodAPIToken)
	assert.Equal(t, AuthMethod("oidc"), AuthMethodOIDC)
}

func TestDefaultAudience(t *testing.T) {
	assert.Equal(t, "https://api.tracevault.io", DefaultAudience)
}
