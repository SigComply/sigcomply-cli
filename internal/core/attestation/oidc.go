package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OIDCProvider represents a CI provider that supports OIDC tokens.
type OIDCProvider string

const (
	// ProviderGitHubActions represents GitHub Actions OIDC provider.
	ProviderGitHubActions OIDCProvider = "github-actions"
	// ProviderGitLabCI represents GitLab CI OIDC provider.
	ProviderGitLabCI OIDCProvider = "gitlab-ci"
	// ProviderUnknown represents an unknown OIDC provider.
	ProviderUnknown OIDCProvider = "unknown"
)

// OIDCToken represents an OIDC token from a CI provider.
type OIDCToken struct {
	// Token is the raw JWT token.
	Token string `json:"token"`

	// Provider is the CI provider that issued the token.
	Provider OIDCProvider `json:"provider"`

	// Subject is the token subject claim.
	Subject string `json:"subject,omitempty"`

	// Issuer is the token issuer.
	Issuer string `json:"issuer,omitempty"`

	// Audience is the token audience.
	Audience string `json:"audience,omitempty"`

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// OIDCSigner signs attestations using OIDC tokens from CI providers.
// The OIDC token itself serves as the signature, allowing the SigComply
// Cloud API to verify the signature using the CI provider's public keys.
type OIDCSigner struct {
	token *OIDCToken
}

// NewOIDCSigner creates a new OIDC signer with the given token.
func NewOIDCSigner(token *OIDCToken) *OIDCSigner {
	return &OIDCSigner{
		token: token,
	}
}

// Algorithm returns the signing algorithm identifier.
func (s *OIDCSigner) Algorithm() string {
	return AlgorithmOIDCJWT
}

// Sign signs the attestation using the OIDC token.
// The token itself is used as the signature value.
func (s *OIDCSigner) Sign(attestation *Attestation) error {
	if s.token == nil || s.token.Token == "" {
		return fmt.Errorf("OIDC token is required for signing")
	}

	// Set signature on attestation
	// The JWT token serves as the signature - the Cloud API can verify it
	// using the CI provider's OIDC public keys (JWKS)
	attestation.Signature = Signature{
		Algorithm: AlgorithmOIDCJWT,
		Value:     s.token.Token,
		KeyID:     string(s.token.Provider),
	}

	return nil
}

// TokenProvider defines the interface for obtaining OIDC tokens.
type TokenProvider interface {
	// GetToken obtains an OIDC token from the CI environment.
	GetToken(ctx context.Context, audience string) (*OIDCToken, error)

	// Provider returns the OIDC provider type.
	Provider() OIDCProvider

	// Available returns true if this provider is available in the current environment.
	Available() bool
}

// GitHubActionsTokenProvider obtains OIDC tokens from GitHub Actions.
type GitHubActionsTokenProvider struct {
	httpClient *http.Client
}

// NewGitHubActionsTokenProvider creates a new GitHub Actions token provider.
func NewGitHubActionsTokenProvider() *GitHubActionsTokenProvider {
	return &GitHubActionsTokenProvider{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Provider returns the OIDC provider type.
func (p *GitHubActionsTokenProvider) Provider() OIDCProvider {
	return ProviderGitHubActions
}

// Available returns true if GitHub Actions OIDC is available.
func (p *GitHubActionsTokenProvider) Available() bool {
	return os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}

// GetToken obtains an OIDC token from GitHub Actions.
// The audience parameter specifies the intended recipient of the token.
func (p *GitHubActionsTokenProvider) GetToken(ctx context.Context, audience string) (*OIDCToken, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if requestURL == "" || requestToken == "" {
		return nil, fmt.Errorf("GitHub Actions OIDC not available: missing ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	}

	// Add audience to URL if specified
	if audience != "" {
		if strings.Contains(requestURL, "?") {
			requestURL += "&audience=" + audience
		} else {
			requestURL += "?audience=" + audience
		}
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request OIDC token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close() //nolint:errcheck // Best effort close, error not actionable
	}()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("OIDC token request failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("OIDC token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC token response: %w", err)
	}

	if tokenResp.Value == "" {
		return nil, fmt.Errorf("empty OIDC token received")
	}

	return &OIDCToken{
		Token:    tokenResp.Value,
		Provider: ProviderGitHubActions,
		Audience: audience,
		Issuer:   "https://token.actions.githubusercontent.com",
	}, nil
}

// GitLabCITokenProvider obtains OIDC tokens from GitLab CI.
type GitLabCITokenProvider struct{}

// NewGitLabCITokenProvider creates a new GitLab CI token provider.
func NewGitLabCITokenProvider() *GitLabCITokenProvider {
	return &GitLabCITokenProvider{}
}

// Provider returns the OIDC provider type.
func (p *GitLabCITokenProvider) Provider() OIDCProvider {
	return ProviderGitLabCI
}

// Available returns true if GitLab CI OIDC is available.
func (p *GitLabCITokenProvider) Available() bool {
	// GitLab CI provides the JWT directly as an environment variable
	return os.Getenv("CI_JOB_JWT_V2") != ""
}

// GetToken obtains an OIDC token from GitLab CI.
// The audience parameter is ignored for GitLab as the token is pre-generated.
func (p *GitLabCITokenProvider) GetToken(_ context.Context, _ string) (*OIDCToken, error) {
	token := os.Getenv("CI_JOB_JWT_V2")
	if token == "" {
		return nil, fmt.Errorf("GitLab CI OIDC not available: CI_JOB_JWT_V2 not set")
	}

	// Get GitLab server URL for issuer
	serverURL := os.Getenv("CI_SERVER_URL")
	if serverURL == "" {
		serverURL = "https://gitlab.com"
	}

	return &OIDCToken{
		Token:    token,
		Provider: ProviderGitLabCI,
		Issuer:   serverURL,
	}, nil
}

// DetectOIDCProvider detects which OIDC provider is available in the current environment.
func DetectOIDCProvider() OIDCProvider {
	// Check GitHub Actions first
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" {
		return ProviderGitHubActions
	}

	// Check GitLab CI
	if os.Getenv("CI_JOB_JWT_V2") != "" {
		return ProviderGitLabCI
	}

	return ProviderUnknown
}

// GetOIDCTokenProvider returns a token provider for the detected CI environment.
// Returns nil if no OIDC provider is detected.
func GetOIDCTokenProvider() TokenProvider {
	switch DetectOIDCProvider() {
	case ProviderGitHubActions:
		return NewGitHubActionsTokenProvider()
	case ProviderGitLabCI:
		return NewGitLabCITokenProvider()
	default:
		return nil
	}
}

// ObtainOIDCToken is a convenience function that detects the CI environment
// and obtains an OIDC token. Returns nil if OIDC is not available.
func ObtainOIDCToken(ctx context.Context, audience string) (*OIDCToken, error) {
	provider := GetOIDCTokenProvider()
	if provider == nil {
		return nil, nil
	}

	return provider.GetToken(ctx, audience)
}
