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
	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

func TestNewClient_DefaultConfig(t *testing.T) {
	client := NewClient(nil)
	assert.NotNil(t, client)
	assert.Equal(t, "https://api.sigcomply.com", client.config.BaseURL)
	assert.Equal(t, 30*time.Second, client.config.Timeout)
}

func TestNewClient_CustomConfig(t *testing.T) {
	cfg := &ClientConfig{
		BaseURL: "https://custom.api.com",
		Timeout: 10 * time.Second,
	}

	client := NewClient(cfg)
	assert.Equal(t, "https://custom.api.com", client.config.BaseURL)
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

// newOIDCClient creates a client configured with an OIDC token for testing.
func newOIDCClient(baseURL string, timeout time.Duration) *Client {
	client := NewClient(&ClientConfig{
		BaseURL: baseURL,
		Timeout: timeout,
	})
	client.WithOIDCToken(&TokenInfo{
		Token:    "test-oidc-token",
		Provider: "github-actions",
	})
	return client
}

func TestClient_Submit_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/cli/runs", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer test-oidc-token")
		assert.Equal(t, "github-actions", r.Header.Get("X-OIDC-Provider"))

		// Return response in the Rails API format (nested structure)
		resp := SubmitResponse{
			Data: &SubmitResponseData{
				Run: &RunResponseData{
					ID:                 "run-123",
					AttestationID:      456,
					PolicyEvaluationID: 789,
					Status:             "accepted",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // Test server - error handling not critical
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newOIDCClient(server.URL, 5*time.Second)

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
			Bucket:  "my-bucket",
			Path:    "evidence",
			URL:     "s3://my-bucket/evidence",
		},
	}

	resp, err := client.Submit(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.Success())
	assert.Equal(t, "run-123", resp.RunID())
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

	client := newOIDCClient(server.URL, 1*time.Second)

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

	client := newOIDCClient(server.URL, 1*time.Second)

	_, err := client.Submit(context.Background(), &SubmitRequest{
		CheckResult: &evidence.CheckResult{},
	})
	require.Error(t, err)

	apiErr, ok := err.(*APIError)
	require.True(t, ok)
	assert.Equal(t, "invalid_request", apiErr.Code)
	assert.Equal(t, "missing required field", apiErr.Message)
}

func TestClient_Submit_NestedErrorFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		//nolint:errcheck // Test server
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "authentication_failed",
				"message": "Invalid or expired OIDC token",
			},
		})
	}))
	defer server.Close()

	client := newOIDCClient(server.URL, 1*time.Second)

	_, err := client.Submit(context.Background(), &SubmitRequest{
		CheckResult: &evidence.CheckResult{},
	})
	require.Error(t, err)

	apiErr, ok := err.(*APIError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, apiErr.HTTPStatus)
	assert.Equal(t, "authentication_failed", apiErr.Code)
	assert.Equal(t, "Invalid or expired OIDC token", apiErr.Message)
}

func TestClient_Submit_402SubscriptionRequired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		//nolint:errcheck // Test server
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":        "subscription_required",
				"message":     "Pro subscription required for cloud submission",
				"upgrade_url": "https://sigcomply.com/customer/settings/subscription",
			},
		})
	}))
	defer server.Close()

	client := newOIDCClient(server.URL, 1*time.Second)

	_, err := client.Submit(context.Background(), &SubmitRequest{
		CheckResult: &evidence.CheckResult{},
	})
	require.Error(t, err)

	apiErr, ok := err.(*APIError)
	require.True(t, ok)
	assert.Equal(t, http.StatusPaymentRequired, apiErr.HTTPStatus)
	assert.Equal(t, "subscription_required", apiErr.Code)
	assert.Equal(t, "Pro subscription required for cloud submission", apiErr.Message)
	assert.True(t, apiErr.IsSubscriptionRequired())
	assert.Equal(t, "https://sigcomply.com/customer/settings/subscription", apiErr.UpgradeURL())
}

func TestClient_Submit_NestedErrorWithDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		//nolint:errcheck // Test server
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "validation_error",
				"message": "Invalid attestation format",
				"details": map[string]interface{}{
					"field": "attestation.hashes.combined",
				},
			},
		})
	}))
	defer server.Close()

	client := newOIDCClient(server.URL, 1*time.Second)

	_, err := client.Submit(context.Background(), &SubmitRequest{
		CheckResult: &evidence.CheckResult{},
	})
	require.Error(t, err)

	apiErr, ok := err.(*APIError)
	require.True(t, ok)
	assert.Equal(t, "validation_error", apiErr.Code)
	assert.Equal(t, "Invalid attestation format", apiErr.Message)
	assert.Equal(t, "attestation.hashes.combined", apiErr.Details["field"])
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

func TestAPIError_IsSubscriptionRequired(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		expected bool
	}{
		{
			name:     "402 status",
			err:      &APIError{HTTPStatus: 402, Code: "subscription_required"},
			expected: true,
		},
		{
			name:     "401 status",
			err:      &APIError{HTTPStatus: 401, Code: "unauthorized"},
			expected: false,
		},
		{
			name:     "200 status",
			err:      &APIError{HTTPStatus: 200},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.IsSubscriptionRequired())
		})
	}
}

func TestAPIError_UpgradeURL(t *testing.T) {
	t.Run("with upgrade URL", func(t *testing.T) {
		err := &APIError{
			HTTPStatus: 402,
			Details: map[string]interface{}{
				"upgrade_url": "https://sigcomply.com/upgrade",
			},
		}
		assert.Equal(t, "https://sigcomply.com/upgrade", err.UpgradeURL())
	})

	t.Run("without details", func(t *testing.T) {
		err := &APIError{HTTPStatus: 402}
		assert.Empty(t, err.UpgradeURL())
	})

	t.Run("without upgrade URL in details", func(t *testing.T) {
		err := &APIError{
			HTTPStatus: 402,
			Details:    map[string]interface{}{"other": "value"},
		}
		assert.Empty(t, err.UpgradeURL())
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "https://api.sigcomply.com", cfg.BaseURL)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
	assert.Equal(t, 3, cfg.RetryCount)
	assert.Equal(t, "sigcomply-cli/1.0", cfg.UserAgent)
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
	// Test the new nested response structure matching Rails API
	resp := &SubmitResponse{
		Data: &SubmitResponseData{
			Run: &RunResponseData{
				ID:                 "run-123",
				AttestationID:      456,
				PolicyEvaluationID: 789,
				Status:             "accepted",
				DriftSummary: &DriftSummary{
					HasDrift:           true,
					NewViolations:      3,
					ResolvedViolations: 1,
					ScoreChange:        -5.5,
					ChangedPolicies: []PolicyChange{
						{
							PolicyCode: "soc2-cc6.1-mfa",
							Change:     "new_violation",
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var parsed SubmitResponse
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	// Test convenience methods
	assert.True(t, parsed.Success())
	assert.Equal(t, "run-123", parsed.RunID())

	// Test direct access
	require.NotNil(t, parsed.Data)
	require.NotNil(t, parsed.Data.Run)
	assert.Equal(t, int64(456), parsed.Data.Run.AttestationID)
	assert.Equal(t, "accepted", parsed.Data.Run.Status)

	// Test drift summary
	driftSummary := parsed.GetDriftSummary()
	require.NotNil(t, driftSummary)
	assert.True(t, driftSummary.HasDrift)
	assert.Equal(t, 3, driftSummary.NewViolations)
	assert.Equal(t, -5.5, driftSummary.ScoreChange)
	require.Len(t, driftSummary.ChangedPolicies, 1)
	assert.Equal(t, "soc2-cc6.1-mfa", driftSummary.ChangedPolicies[0].PolicyCode)
	assert.Equal(t, "new_violation", driftSummary.ChangedPolicies[0].Change)
}

func TestSubmitResponse_ConvenienceMethods(t *testing.T) {
	t.Run("nil response", func(t *testing.T) {
		var resp *SubmitResponse
		assert.False(t, resp.Success())
		assert.Empty(t, resp.RunID())
		assert.Nil(t, resp.GetDriftSummary())
	})

	t.Run("nil data", func(t *testing.T) {
		resp := &SubmitResponse{}
		assert.False(t, resp.Success())
		assert.Empty(t, resp.RunID())
		assert.Nil(t, resp.GetDriftSummary())
	})

	t.Run("nil run", func(t *testing.T) {
		resp := &SubmitResponse{Data: &SubmitResponseData{}}
		assert.False(t, resp.Success())
		assert.Empty(t, resp.RunID())
		assert.Nil(t, resp.GetDriftSummary())
	})

	t.Run("non-accepted status", func(t *testing.T) {
		resp := &SubmitResponse{
			Data: &SubmitResponseData{
				Run: &RunResponseData{
					ID:     "run-123",
					Status: "pending",
				},
			},
		}
		assert.False(t, resp.Success())
		assert.Equal(t, "run-123", resp.RunID())
	})
}
