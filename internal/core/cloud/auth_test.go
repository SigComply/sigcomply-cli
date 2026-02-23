package cloud

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
)

// Test helper functions for env var management
func setEnv(key, value string) {
	_ = os.Setenv(key, value) //nolint:errcheck // Test helper, error not critical
}

func unsetEnv(key string) {
	_ = os.Unsetenv(key) //nolint:errcheck // Test helper, error not critical
}

// saveAndClearOIDCEnv saves current OIDC env vars and clears them.
// Returns a cleanup function to restore original values.
func saveAndClearOIDCEnv(t *testing.T) {
	t.Helper()
	originalGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalGLJWT := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
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
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	unsetEnv("CI_JOB_JWT_V2")
}

func TestDetectAuth_NoAuth(t *testing.T) {
	saveAndClearOIDCEnv(t)

	ctx := context.Background()
	result, err := DetectAuth(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodNone, result.Method)
	assert.Empty(t, result.Token)
}

func TestDetectAuth_GitLabCI(t *testing.T) {
	saveAndClearOIDCEnv(t)
	setEnv("CI_JOB_JWT_V2", "gitlab-jwt-token")

	ctx := context.Background()
	result, err := DetectAuth(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodOIDC, result.Method)
	assert.Equal(t, "gitlab-jwt-token", result.Token)
	assert.Equal(t, attestation.ProviderGitLabCI, result.OIDCProvider)
}

func TestDetectAuth_DefaultAudience(t *testing.T) {
	saveAndClearOIDCEnv(t)
	setEnv("CI_JOB_JWT_V2", "gitlab-jwt-token")

	ctx := context.Background()
	cfg := &AuthConfig{} // Empty audience should use default
	result, err := DetectAuth(ctx, cfg)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodOIDC, result.Method)
}

func TestDetectAuth_CustomAudience(t *testing.T) {
	saveAndClearOIDCEnv(t)
	setEnv("CI_JOB_JWT_V2", "gitlab-jwt-token")

	ctx := context.Background()
	cfg := &AuthConfig{OIDCAudience: "https://custom.api.com"}
	result, err := DetectAuth(ctx, cfg)

	require.NoError(t, err)
	assert.Equal(t, AuthMethodOIDC, result.Method)
}

func TestConfigureClientAuth_NoAuth(t *testing.T) {
	saveAndClearOIDCEnv(t)

	ctx := context.Background()
	client := NewClient(nil)
	err := ConfigureClientAuth(ctx, client, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authentication available")
	assert.Contains(t, err.Error(), "OIDC support")
}

func TestConfigureClientAuth_WithOIDC(t *testing.T) {
	saveAndClearOIDCEnv(t)
	setEnv("CI_JOB_JWT_V2", "gitlab-jwt-token")

	ctx := context.Background()
	client := NewClient(nil)
	err := ConfigureClientAuth(ctx, client, nil)

	require.NoError(t, err)
	assert.True(t, client.IsConfigured())
	assert.Equal(t, "gitlab-jwt-token", client.config.OIDCToken.Token)
}

func TestNewAuthenticatedClient_Success(t *testing.T) {
	saveAndClearOIDCEnv(t)
	setEnv("CI_JOB_JWT_V2", "gitlab-jwt-token")

	ctx := context.Background()
	client, err := NewAuthenticatedClient(ctx, nil)

	require.NoError(t, err)
	require.NotNil(t, client)
	assert.True(t, client.IsConfigured())
}

func TestNewAuthenticatedClient_NoAuth(t *testing.T) {
	saveAndClearOIDCEnv(t)

	ctx := context.Background()
	client, err := NewAuthenticatedClient(ctx, nil)

	require.Error(t, err)
	assert.Nil(t, client)
}

func TestMustNewAuthenticatedClient_ReturnsUnconfiguredOnError(t *testing.T) {
	saveAndClearOIDCEnv(t)

	ctx := context.Background()
	client := MustNewAuthenticatedClient(ctx, nil)

	require.NotNil(t, client)
	assert.False(t, client.IsConfigured())
}

func TestIsOIDCAvailable(t *testing.T) {
	saveAndClearOIDCEnv(t)

	// Not available when no OIDC env vars
	assert.False(t, IsOIDCAvailable())

	// Available when GitLab CI
	setEnv("CI_JOB_JWT_V2", "token")
	assert.True(t, IsOIDCAvailable())
}

func TestGetOIDCProvider(t *testing.T) {
	saveAndClearOIDCEnv(t)

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
		Audience: "https://api.sigcomply.com",
	}

	tokenInfo := TokenInfoFromOIDC(oidcToken)
	require.NotNil(t, tokenInfo)
	assert.Equal(t, "test-token", tokenInfo.Token)
	assert.Equal(t, "github-actions", tokenInfo.Provider)
	assert.Equal(t, "repo:owner/repo:ref:refs/heads/main", tokenInfo.Subject)
	assert.Equal(t, "https://token.actions.githubusercontent.com", tokenInfo.Issuer)
	assert.Equal(t, "https://api.sigcomply.com", tokenInfo.Audience)
}

func TestRefreshableAuth_NeedsRefresh(t *testing.T) {
	client := NewClient(nil)
	auth := NewRefreshableAuth(client, nil)

	// Needs refresh when result is nil
	assert.True(t, auth.NeedsRefresh())

	// Set a result with OIDC method
	auth.result = &AuthResult{
		Method: AuthMethodOIDC,
		Token:  "token",
	}
	// Just set, so not yet expired
	// obtained is zero time — should trigger refresh
	assert.True(t, auth.NeedsRefresh())
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
	assert.Equal(t, AuthMethod("oidc"), AuthMethodOIDC)
}

func TestDefaultAudience(t *testing.T) {
	assert.Equal(t, "https://api.sigcomply.com", DefaultAudience)
}
