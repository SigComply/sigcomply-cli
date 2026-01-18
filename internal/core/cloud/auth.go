// Package cloud provides the TraceVault Cloud API client.
package cloud

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/tracevault/tracevault-cli/internal/core/attestation"
)

// DefaultAudience is the default audience for TraceVault OIDC tokens.
const DefaultAudience = "https://api.tracevault.io"

// AuthConfig holds authentication configuration options.
type AuthConfig struct {
	// APIToken is a static API token (takes precedence over OIDC).
	APIToken string

	// OIDCAudience is the audience to request for OIDC tokens.
	// Defaults to DefaultAudience.
	OIDCAudience string

	// PreferOIDC indicates whether to prefer OIDC over API token.
	// When false (default), API token takes precedence if both are available.
	PreferOIDC bool
}

// AuthResult contains the result of authentication detection.
type AuthResult struct {
	// Method is the authentication method detected.
	Method AuthMethod

	// Token is the authentication token (API token or OIDC JWT).
	Token string

	// OIDCProvider is the OIDC provider (if using OIDC).
	OIDCProvider attestation.OIDCProvider

	// OIDCToken contains the full OIDC token info (if using OIDC).
	OIDCToken *attestation.OIDCToken
}

// AuthMethod represents the authentication method used.
type AuthMethod string

const (
	// AuthMethodNone indicates no authentication is configured.
	AuthMethodNone AuthMethod = "none"
	// AuthMethodAPIToken indicates static API token authentication.
	AuthMethodAPIToken AuthMethod = "api-token"
	// AuthMethodOIDC indicates OIDC token authentication.
	AuthMethodOIDC AuthMethod = "oidc"
)

// DetectAuth detects available authentication methods and returns the best option.
// Priority: API Token > OIDC (unless PreferOIDC is true)
func DetectAuth(ctx context.Context, cfg *AuthConfig) (*AuthResult, error) {
	if cfg == nil {
		cfg = &AuthConfig{}
	}

	// Fill in defaults
	if cfg.OIDCAudience == "" {
		cfg.OIDCAudience = DefaultAudience
	}

	// Check for API token from config or environment
	apiToken := cfg.APIToken
	if apiToken == "" {
		apiToken = os.Getenv("TRACEVAULT_API_TOKEN")
	}

	// Check for OIDC token availability
	oidcProvider := attestation.GetOIDCTokenProvider()

	// Determine which auth method to use
	hasAPIToken := apiToken != ""
	hasOIDC := oidcProvider != nil

	if !hasAPIToken && !hasOIDC {
		return &AuthResult{Method: AuthMethodNone}, nil
	}

	// If preferring OIDC and it's available, use it
	if cfg.PreferOIDC && hasOIDC {
		return obtainOIDCAuth(ctx, oidcProvider, cfg.OIDCAudience)
	}

	// If API token is available, use it (default preference)
	if hasAPIToken {
		return &AuthResult{
			Method: AuthMethodAPIToken,
			Token:  apiToken,
		}, nil
	}

	// Fall back to OIDC if available
	if hasOIDC {
		return obtainOIDCAuth(ctx, oidcProvider, cfg.OIDCAudience)
	}

	return &AuthResult{Method: AuthMethodNone}, nil
}

// obtainOIDCAuth obtains an OIDC token from the provider.
func obtainOIDCAuth(ctx context.Context, provider attestation.TokenProvider, audience string) (*AuthResult, error) {
	oidcToken, err := provider.GetToken(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain OIDC token: %w", err)
	}

	return &AuthResult{
		Method:       AuthMethodOIDC,
		Token:        oidcToken.Token,
		OIDCProvider: oidcToken.Provider,
		OIDCToken:    oidcToken,
	}, nil
}

// ConfigureClientAuth configures a Cloud client with the best available authentication.
// Returns an error if no authentication is available.
func ConfigureClientAuth(ctx context.Context, client *Client, cfg *AuthConfig) error {
	result, err := DetectAuth(ctx, cfg)
	if err != nil {
		return err
	}

	switch result.Method {
	case AuthMethodNone:
		return fmt.Errorf("no authentication available: set TRACEVAULT_API_TOKEN or run in a CI environment with OIDC support")

	case AuthMethodAPIToken:
		client.WithAPIToken(result.Token)

	case AuthMethodOIDC:
		client.WithOIDCToken(&TokenInfo{
			Token:    result.Token,
			Provider: string(result.OIDCProvider),
		})
	}

	return nil
}

// NewAuthenticatedClient creates a new Cloud client with auto-detected authentication.
// Returns an error if no authentication is available.
func NewAuthenticatedClient(ctx context.Context, cfg *AuthConfig) (*Client, error) {
	client := NewClient(nil)

	if err := ConfigureClientAuth(ctx, client, cfg); err != nil {
		return nil, err
	}

	return client, nil
}

// MustNewAuthenticatedClient creates a new Cloud client with auto-detected authentication.
// Returns an unauthenticated client if no authentication is available.
func MustNewAuthenticatedClient(ctx context.Context, cfg *AuthConfig) *Client {
	client, err := NewAuthenticatedClient(ctx, cfg)
	if err != nil {
		// Return an unauthenticated client
		return NewClient(nil)
	}
	return client
}

// IsOIDCAvailable checks if OIDC authentication is available in the current environment.
func IsOIDCAvailable() bool {
	return attestation.GetOIDCTokenProvider() != nil
}

// GetOIDCProvider returns the detected OIDC provider, or ProviderUnknown if none.
func GetOIDCProvider() attestation.OIDCProvider {
	return attestation.DetectOIDCProvider()
}

// ObtainOIDCToken obtains an OIDC token from the current CI environment.
// Returns nil, nil if OIDC is not available.
func ObtainOIDCToken(ctx context.Context, audience string) (*attestation.OIDCToken, error) {
	return attestation.ObtainOIDCToken(ctx, audience)
}

// TokenInfo converts an attestation.OIDCToken to cloud.TokenInfo.
func oidcTokenToTokenInfo(token *attestation.OIDCToken) *TokenInfo {
	if token == nil {
		return nil
	}
	return &TokenInfo{
		Token:     token.Token,
		Provider:  string(token.Provider),
		Subject:   token.Subject,
		Issuer:    token.Issuer,
		Audience:  token.Audience,
		ExpiresAt: token.ExpiresAt,
	}
}

// TokenInfoFromOIDC converts an attestation.OIDCToken to cloud.TokenInfo.
// This is a public helper for external use.
func TokenInfoFromOIDC(token *attestation.OIDCToken) *TokenInfo {
	return oidcTokenToTokenInfo(token)
}

// RefreshableAuth provides authentication that can be refreshed.
// This is useful for long-running processes that may need to refresh tokens.
type RefreshableAuth struct {
	config   *AuthConfig
	client   *Client
	result   *AuthResult
	obtained time.Time
}

// NewRefreshableAuth creates a new refreshable auth wrapper.
func NewRefreshableAuth(client *Client, cfg *AuthConfig) *RefreshableAuth {
	return &RefreshableAuth{
		config: cfg,
		client: client,
	}
}

// Refresh re-obtains authentication and configures the client.
func (r *RefreshableAuth) Refresh(ctx context.Context) error {
	if err := ConfigureClientAuth(ctx, r.client, r.config); err != nil {
		return err
	}

	// DetectAuth shouldn't fail if ConfigureClientAuth succeeded,
	// but handle the error for completeness
	result, err := DetectAuth(ctx, r.config)
	if err != nil {
		return err
	}
	r.result = result
	r.obtained = time.Now()

	return nil
}

// NeedsRefresh returns true if the authentication might need refreshing.
// OIDC tokens typically expire after a few minutes.
func (r *RefreshableAuth) NeedsRefresh() bool {
	if r.result == nil {
		return true
	}

	// OIDC tokens typically expire quickly, refresh after 2 minutes
	if r.result.Method == AuthMethodOIDC {
		return time.Since(r.obtained) > 2*time.Minute
	}

	// API tokens don't need refresh
	return false
}

// Method returns the current authentication method.
func (r *RefreshableAuth) Method() AuthMethod {
	if r.result == nil {
		return AuthMethodNone
	}
	return r.result.Method
}
