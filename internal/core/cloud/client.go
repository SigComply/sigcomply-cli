package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// Client is the TraceVault Cloud API client.
type Client struct {
	config     *ClientConfig
	httpClient *http.Client
}

// NewClient creates a new Cloud API client.
func NewClient(cfg *ClientConfig) *Client {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// NewClientFromEnv creates a client configured from environment variables.
func NewClientFromEnv() *Client {
	cfg := DefaultConfig()

	if url := os.Getenv("TRACEVAULT_API_URL"); url != "" {
		cfg.BaseURL = url
	}

	if token := os.Getenv("TRACEVAULT_API_TOKEN"); token != "" {
		cfg.APIToken = token
	}

	return NewClient(cfg)
}

// WithAPIToken sets the API token for authentication.
func (c *Client) WithAPIToken(token string) *Client {
	c.config.APIToken = token
	return c
}

// WithOIDCToken sets the OIDC token for authentication.
func (c *Client) WithOIDCToken(token *TokenInfo) *Client {
	c.config.OIDCToken = token
	return c
}

// WithBaseURL sets the API base URL.
func (c *Client) WithBaseURL(url string) *Client {
	c.config.BaseURL = url
	return c
}

// IsConfigured returns true if the client has valid authentication.
func (c *Client) IsConfigured() bool {
	return c.config.APIToken != "" || (c.config.OIDCToken != nil && c.config.OIDCToken.Token != "")
}

// Submit sends compliance check results to the Cloud API.
func (c *Client) Submit(ctx context.Context, req *SubmitRequest) (*SubmitResponse, error) {
	if !c.IsConfigured() {
		return nil, &APIError{
			Code:    "not_configured",
			Message: "client is not configured with authentication",
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.BaseURL+"/api/v1/cli/runs", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.doWithRetry(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // Response body close errors are not critical

	if resp.StatusCode >= 400 {
		return nil, c.parseError(resp)
	}

	var result SubmitResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// HealthCheck verifies connectivity to the Cloud API.
func (c *Client) HealthCheck(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.BaseURL+"/api/v1/health", http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Response body close errors are not critical

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}

	return nil
}

// setHeaders sets the common HTTP headers.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.config.UserAgent)

	// Set authentication header
	if c.config.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIToken)
	} else if c.config.OIDCToken != nil && c.config.OIDCToken.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.OIDCToken.Token)
		req.Header.Set("X-OIDC-Provider", c.config.OIDCToken.Provider)
	}
}

// doWithRetry executes an HTTP request with retry logic.
// Note: This doesn't support retrying requests with bodies since the body is consumed.
// For Submit requests, we recreate the request in the Submit method.
func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Don't retry - caller should handle retries for POST requests with bodies
	return resp, nil
}

// parseError parses an error response from the API.
func (c *Client) parseError(resp *http.Response) *APIError {
	body, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error details

	apiErr := &APIError{
		HTTPStatus: resp.StatusCode,
		Message:    http.StatusText(resp.StatusCode),
	}

	// Try to parse as JSON error
	var jsonErr struct {
		Error   string                 `json:"error"`
		Code    string                 `json:"code"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details"`
	}
	if err := json.Unmarshal(body, &jsonErr); err == nil {
		if jsonErr.Code != "" {
			apiErr.Code = jsonErr.Code
		}
		if jsonErr.Message != "" {
			apiErr.Message = jsonErr.Message
		} else if jsonErr.Error != "" {
			apiErr.Message = jsonErr.Error
		}
		apiErr.Details = jsonErr.Details
	}

	return apiErr
}

// DetectOIDCToken attempts to detect OIDC tokens from CI environment.
func DetectOIDCToken() *TokenInfo {
	// GitHub Actions OIDC
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		if token := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"); token != "" {
			return &TokenInfo{
				Token:    token,
				Provider: "github-actions",
			}
		}
	}

	// GitLab CI OIDC
	if os.Getenv("GITLAB_CI") == "true" {
		if token := os.Getenv("CI_JOB_JWT_V2"); token != "" {
			return &TokenInfo{
				Token:    token,
				Provider: "gitlab-ci",
			}
		}
	}

	return nil
}
