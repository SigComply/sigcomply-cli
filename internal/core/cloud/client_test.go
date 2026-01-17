package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tracevault/tracevault-cli/internal/core/attestation"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

func TestNewClient_DefaultConfig(t *testing.T) {
	client := NewClient(nil)
	assert.NotNil(t, client)
	assert.Equal(t, "https://api.tracevault.com", client.config.BaseURL)
	assert.Equal(t, 30*time.Second, client.config.Timeout)
}

func TestNewClient_CustomConfig(t *testing.T) {
	cfg := &ClientConfig{
		BaseURL:  "https://custom.api.com",
		APIToken: "test-token",
		Timeout:  10 * time.Second,
	}

	client := NewClient(cfg)
	assert.Equal(t, "https://custom.api.com", client.config.BaseURL)
	assert.Equal(t, "test-token", client.config.APIToken)
}

func TestClient_WithAPIToken(t *testing.T) {
	client := NewClient(nil).WithAPIToken("my-token")
	assert.Equal(t, "my-token", client.config.APIToken)
}

func TestClient_WithOIDCToken(t *testing.T) {
	token := &TokenInfo{
		Token:    "oidc-token",
		Provider: "github-actions",
	}
	client := NewClient(nil).WithOIDCToken(token)
	assert.Equal(t, "oidc-token", client.config.OIDCToken.Token)
	assert.Equal(t, "github-actions", client.config.OIDCToken.Provider)
}

func TestClient_WithBaseURL(t *testing.T) {
	client := NewClient(nil).WithBaseURL("https://localhost:8080")
	assert.Equal(t, "https://localhost:8080", client.config.BaseURL)
}

func TestClient_IsConfigured(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*Client)
		expected bool
	}{
		{
			name:     "not configured",
			setup:    func(c *Client) {},
			expected: false,
		},
		{
			name: "with API token",
			setup: func(c *Client) {
				c.config.APIToken = "token"
			},
			expected: true,
		},
		{
			name: "with OIDC token",
			setup: func(c *Client) {
				c.config.OIDCToken = &TokenInfo{Token: "oidc-token"}
			},
			expected: true,
		},
		{
			name: "with empty OIDC token",
			setup: func(c *Client) {
				c.config.OIDCToken = &TokenInfo{Token: ""}
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)
			tt.setup(client)
			assert.Equal(t, tt.expected, client.IsConfigured())
		})
	}
}

func TestClient_Submit_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/runs", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer test-token")

		resp := SubmitResponse{
			Success:      true,
			RunID:        "run-123",
			Message:      "Submission accepted",
			DashboardURL: "https://app.tracevault.com/runs/run-123",
		}
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // Test server - error handling not critical
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		BaseURL:  server.URL,
		APIToken: "test-token",
		Timeout:  5 * time.Second,
	})

	req := &SubmitRequest{
		CheckResult: &evidence.CheckResult{
			RunID:     "run-123",
			Framework: "soc2",
			Timestamp: time.Now(),
		},
		Attestation: &attestation.Attestation{
			ID:        "attest-123",
			RunID:     "run-123",
			Framework: "soc2",
		},
		EvidenceLocation: &EvidenceLocation{
			Backend: "s3",
			Path:    "s3://my-bucket/evidence",
		},
	}

	resp, err := client.Submit(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "run-123", resp.RunID)
	assert.Contains(t, resp.DashboardURL, "run-123")
}

func TestClient_Submit_NotConfigured(t *testing.T) {
	client := NewClient(nil)

	resp, err := client.Submit(context.Background(), &SubmitRequest{})
	assert.Nil(t, resp)
	require.Error(t, err)

	apiErr, ok := err.(*APIError)
	require.True(t, ok)
	assert.Equal(t, "not_configured", apiErr.Code)
}

func TestClient_Submit_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		//nolint:errcheck // Test server - error handling not critical
		json.NewEncoder(w).Encode(map[string]string{
			"error": "internal server error",
		})
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		BaseURL:  server.URL,
		APIToken: "test-token",
		Timeout:  1 * time.Second,
	})

	_, err := client.Submit(context.Background(), &SubmitRequest{
		CheckResult: &evidence.CheckResult{},
	})
	require.Error(t, err)

	apiErr, ok := err.(*APIError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, apiErr.HTTPStatus)
}

func TestClient_Submit_ClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		//nolint:errcheck // Test server - error handling not critical
		json.NewEncoder(w).Encode(map[string]string{
			"code":    "invalid_request",
			"message": "missing required field",
		})
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		BaseURL:  server.URL,
		APIToken: "test-token",
		Timeout:  1 * time.Second,
	})

	_, err := client.Submit(context.Background(), &SubmitRequest{
		CheckResult: &evidence.CheckResult{},
	})
	require.Error(t, err)

	apiErr, ok := err.(*APIError)
	require.True(t, ok)
	assert.Equal(t, "invalid_request", apiErr.Code)
	assert.Equal(t, "missing required field", apiErr.Message)
}

func TestClient_HealthCheck_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/health", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	err := client.HealthCheck(context.Background())
	assert.NoError(t, err)
}

func TestClient_HealthCheck_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		//nolint:errcheck // Test server - error handling not critical
		json.NewEncoder(w).Encode(map[string]string{
			"error": "service unavailable",
		})
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	err := client.HealthCheck(context.Background())
	require.Error(t, err)

	apiErr, ok := err.(*APIError)
	require.True(t, ok)
	assert.Equal(t, http.StatusServiceUnavailable, apiErr.HTTPStatus)
}

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		expected string
	}{
		{
			name: "with code and message",
			err: &APIError{
				Code:    "invalid_request",
				Message: "missing field",
			},
			expected: "invalid_request: missing field",
		},
		{
			name: "message only",
			err: &APIError{
				Message: "something went wrong",
			},
			expected: "something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "https://api.tracevault.com", cfg.BaseURL)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
	assert.Equal(t, 3, cfg.RetryCount)
	assert.Equal(t, "tracevault-cli/1.0", cfg.UserAgent)
}

func TestDetectOIDCToken_NoCI(t *testing.T) {
	token := DetectOIDCToken()
	// In a non-CI environment, this should return nil
	// (unless tests are running in CI, in which case this test would need adjustment)
	if token != nil {
		// If running in CI, verify the token is valid
		assert.NotEmpty(t, token.Token)
		assert.NotEmpty(t, token.Provider)
	}
}

func TestSubmitRequest_JSON(t *testing.T) {
	req := &SubmitRequest{
		CheckResult: &evidence.CheckResult{
			RunID:     "run-123",
			Framework: "soc2",
		},
		Attestation: &attestation.Attestation{
			ID:    "attest-123",
			RunID: "run-123",
		},
		EvidenceLocation: &EvidenceLocation{
			Backend:      "s3",
			Path:         "s3://bucket/path",
			ManifestPath: "manifest.json",
		},
		RunMetadata: &RunMetadata{
			CI:         true,
			CIProvider: "github-actions",
			Repository: "owner/repo",
			Branch:     "main",
			CommitSHA:  "abc123",
		},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var parsed SubmitRequest
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "run-123", parsed.CheckResult.RunID)
	assert.Equal(t, "s3", parsed.EvidenceLocation.Backend)
	assert.True(t, parsed.RunMetadata.CI)
}

func TestSubmitResponse_WithDrift(t *testing.T) {
	resp := &SubmitResponse{
		Success:      true,
		RunID:        "run-123",
		DashboardURL: "https://app.tracevault.com/runs/run-123",
		DriftSummary: &DriftSummary{
			HasDrift:           true,
			NewViolations:      3,
			ResolvedViolations: 1,
			ChangedPolicies: []PolicyChange{
				{
					PolicyID:      "soc2-cc6.1-mfa",
					PreviousState: "pass",
					CurrentState:  "fail",
				},
			},
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var parsed SubmitResponse
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.True(t, parsed.DriftSummary.HasDrift)
	assert.Equal(t, 3, parsed.DriftSummary.NewViolations)
	assert.Len(t, parsed.DriftSummary.ChangedPolicies, 1)
}
