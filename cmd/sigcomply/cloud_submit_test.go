package sigcomply

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sigcomply/sigcomply-cli/internal/core/cloud"
	"github.com/sigcomply/sigcomply-cli/internal/core/config"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

func TestBuildCloudSubmitRequest(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:           "soc2-cc6.1-mfa",
				ControlID:          "CC6.1",
				Status:             evidence.StatusFail,
				Severity:           evidence.SeverityHigh,
				ResourcesEvaluated: 5,
				ResourcesFailed:    2,
				Violations: []evidence.Violation{
					{ResourceID: "arn:aws:iam::123:user/alice", ResourceType: "aws:iam:user", Reason: "MFA not enabled"},
					{ResourceID: "arn:aws:iam::123:user/bob", ResourceType: "aws:iam:user", Reason: "MFA not enabled"},
				},
			},
		},
	}
	checkResult.CalculateSummary()

	cfg := &config.Config{
		Framework:  "soc2",
		CI:         true,
		CIProvider: "github-actions",
		Repository: "owner/repo",
		Branch:     "main",
		CommitSHA:  "abc123",
	}

	req := buildCloudSubmitRequest(cfg, checkResult)

	assert.Equal(t, "run-123", req.CheckResult.RunID)
	assert.Equal(t, "soc2", req.CheckResult.Framework)

	require.Len(t, req.CheckResult.PolicyResults, 1)
	pr := req.CheckResult.PolicyResults[0]
	assert.Equal(t, "soc2-cc6.1-mfa", pr.PolicyID)
	assert.Equal(t, "CC6.1", pr.ControlID)
	assert.Equal(t, "fail", pr.Status)
	assert.Equal(t, "high", pr.Severity)
	assert.Equal(t, 5, pr.ResourcesEvaluated)
	assert.Equal(t, 2, pr.ResourcesFailed)

	// No resource identifiers in the cloud payload
	assert.True(t, req.CheckResult.Environment.CI)
	assert.Equal(t, "github-actions", req.CheckResult.Environment.CIProvider)
	assert.Equal(t, 0.0, req.CheckResult.Summary.ComplianceScore)
}

func TestBuildCloudSubmitRequest_NoViolationsInPayload(t *testing.T) {
	// Verify the aggregation boundary: violations must never appear in the cloud payload.
	checkResult := &evidence.CheckResult{
		RunID:     "run-privacy",
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID: "soc2-cc6.1-mfa",
				Status:   evidence.StatusFail,
				Violations: []evidence.Violation{
					{ResourceID: "arn:aws:iam::123:user/secret-user", ResourceType: "aws:iam:user", Reason: "MFA not enabled"},
				},
				ResourcesEvaluated: 10,
				ResourcesFailed:    1,
			},
		},
	}
	checkResult.CalculateSummary()

	cfg := &config.Config{Framework: "soc2"}
	req := buildCloudSubmitRequest(cfg, checkResult)

	// Marshal to JSON and verify no ARNs appear
	data, err := json.Marshal(req)
	require.NoError(t, err)

	payload := string(data)
	assert.NotContains(t, payload, "arn:aws:iam", "ARNs must not appear in cloud payload")
	assert.NotContains(t, payload, "secret-user", "usernames must not appear in cloud payload")
	assert.NotContains(t, payload, "MFA not enabled", "violation reasons must not appear in cloud payload")

	// Counts should still be present
	assert.Contains(t, payload, `"resources_failed":1`)
}

func TestBuildCloudSubmitRequest_ErrorStatusMappedToFail(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "run-error",
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{PolicyID: "policy-1", Status: evidence.StatusPass},
			{PolicyID: "policy-2", Status: evidence.StatusError, Message: "connection timeout"},
		},
	}
	checkResult.CalculateSummary()

	cfg := &config.Config{Framework: "soc2"}
	req := buildCloudSubmitRequest(cfg, checkResult)

	require.Len(t, req.CheckResult.PolicyResults, 2)
	assert.Equal(t, "pass", req.CheckResult.PolicyResults[0].Status)
	assert.Equal(t, "fail", req.CheckResult.PolicyResults[1].Status, "error should be mapped to fail")

	// Summary should reflect the mapping
	assert.Equal(t, 2, req.CheckResult.Summary.TotalPolicies)
	assert.Equal(t, 1, req.CheckResult.Summary.PassedPolicies)
	assert.Equal(t, 1, req.CheckResult.Summary.FailedPolicies)
}

// setupOIDCEnv sets up OIDC environment for tests and returns cleanup function.
func setupOIDCEnv(t *testing.T) {
	t.Helper()
	origGLJWT := os.Getenv("CI_JOB_JWT_V2")
	origGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	t.Cleanup(func() {
		if origGLJWT != "" {
			os.Setenv("CI_JOB_JWT_V2", origGLJWT) //nolint:errcheck // test env setup // test env cleanup
		} else {
			os.Unsetenv("CI_JOB_JWT_V2") //nolint:errcheck // test env setup // test env cleanup
		}
		if origGHURL != "" {
			os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", origGHURL) //nolint:errcheck // test env setup // test env cleanup
		} else {
			os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL") //nolint:errcheck // test env setup // test env cleanup
		}
	})
}

func TestSubmitToCloud_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/cli/runs", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

		// Verify the request body has the nested check_result structure Rails expects
		var req cloud.SubmitRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.NotEmpty(t, req.CheckResult.RunID)
		assert.NotEmpty(t, req.CheckResult.Framework)
		assert.NotNil(t, req.CheckResult.Environment)

		// Return response in the Rails API format (nested structure)
		resp := cloud.SubmitResponse{
			Data: &cloud.SubmitResponseData{
				Run: &cloud.RunResponseData{
					ID:                 "run-123",
					PolicyEvaluationID: 789,
					Status:             "accepted",
					DriftSummary: &cloud.DriftSummary{
						HasDrift:      true,
						NewViolations: 2,
						ScoreChange:   -5.0,
						ChangedPolicies: []cloud.PolicyChange{
							{PolicyCode: "aws-iam-mfa-enabled", Change: "new_violation"},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test env setup // Test server
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Set up OIDC environment
	setupOIDCEnv(t)
	os.Setenv("CI_JOB_JWT_V2", "test-oidc-token") //nolint:errcheck // test env setup

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
	}

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: ts,
	}
	checkResult.CalculateSummary()

	resp, err := submitToCloud(context.Background(), cfg, checkResult, server.URL)
	require.NoError(t, err)

	// Use convenience methods to access the nested response
	assert.True(t, resp.Success())
	assert.Equal(t, "run-123", resp.RunID())

	// Also verify direct access works
	require.NotNil(t, resp.Data)
	require.NotNil(t, resp.Data.Run)
	assert.Equal(t, int64(789), resp.Data.Run.PolicyEvaluationID)
	assert.Equal(t, "accepted", resp.Data.Run.Status)

	// Check drift summary
	driftSummary := resp.GetDriftSummary()
	require.NotNil(t, driftSummary)
	assert.True(t, driftSummary.HasDrift)
	assert.Equal(t, 2, driftSummary.NewViolations)
	assert.Equal(t, -5.0, driftSummary.ScoreChange)
	require.Len(t, driftSummary.ChangedPolicies, 1)
	assert.Equal(t, "aws-iam-mfa-enabled", driftSummary.ChangedPolicies[0].PolicyCode)
	assert.Equal(t, "new_violation", driftSummary.ChangedPolicies[0].Change)
}

func TestSubmitToCloud_NoOIDC(t *testing.T) {
	setupOIDCEnv(t)
	os.Unsetenv("CI_JOB_JWT_V2")               //nolint:errcheck // test env setup
	os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL") //nolint:errcheck // test env setup

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
	}

	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
	}
	checkResult.CalculateSummary()

	resp, err := submitToCloud(context.Background(), cfg, checkResult, "")
	assert.Nil(t, resp)
	assert.NoError(t, err) // Should not error, just skip
}

func TestSubmitToCloud_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		//nolint:errcheck // test env setup // Test server
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "authentication_failed",
				"message": "invalid token",
			},
		})
	}))
	defer server.Close()

	setupOIDCEnv(t)
	os.Setenv("CI_JOB_JWT_V2", "bad-oidc-token") //nolint:errcheck // test env setup

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
	}

	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
	}
	checkResult.CalculateSummary()

	resp, err := submitToCloud(context.Background(), cfg, checkResult, server.URL)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication_failed")
}

func TestSubmitToCloud_402SubscriptionRequired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		//nolint:errcheck // test env setup // Test server
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":        "subscription_required",
				"message":     "Pro subscription required",
				"upgrade_url": "https://sigcomply.com/customer/settings/subscription",
			},
		})
	}))
	defer server.Close()

	setupOIDCEnv(t)
	os.Setenv("CI_JOB_JWT_V2", "free-tier-oidc-token") //nolint:errcheck // test env setup

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
	}

	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
	}
	checkResult.CalculateSummary()

	resp, err := submitToCloud(context.Background(), cfg, checkResult, server.URL)
	assert.Nil(t, resp)
	require.Error(t, err)

	var apiErr *cloud.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.True(t, apiErr.IsSubscriptionRequired())
	assert.Equal(t, "subscription_required", apiErr.Code)
	assert.Equal(t, "https://sigcomply.com/customer/settings/subscription", apiErr.UpgradeURL())
}

func TestShouldSubmitToCloud(t *testing.T) {
	// Save and restore OIDC env
	origGLJWT := os.Getenv("CI_JOB_JWT_V2")
	origGHURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	defer func() {
		if origGLJWT != "" {
			os.Setenv("CI_JOB_JWT_V2", origGLJWT) //nolint:errcheck // test env setup // test env cleanup
		} else {
			os.Unsetenv("CI_JOB_JWT_V2") //nolint:errcheck // test env setup // test env cleanup
		}
		if origGHURL != "" {
			os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", origGHURL) //nolint:errcheck // test env setup // test env cleanup
		} else {
			os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL") //nolint:errcheck // test env setup // test env cleanup
		}
	}()

	t.Run("no OIDC available returns false", func(t *testing.T) {
		os.Unsetenv("CI_JOB_JWT_V2")               //nolint:errcheck // test env setup
		os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL") //nolint:errcheck // test env setup

		cfg := &config.Config{CloudEnabled: true}
		assert.False(t, shouldSubmitToCloud(cfg, false, false))
	})

	t.Run("no OIDC with --cloud flag still returns false", func(t *testing.T) {
		os.Unsetenv("CI_JOB_JWT_V2")               //nolint:errcheck // test env setup
		os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL") //nolint:errcheck // test env setup

		cfg := &config.Config{CloudEnabled: false}
		assert.False(t, shouldSubmitToCloud(cfg, true, false))
	})

	t.Run("--no-cloud always wins", func(t *testing.T) {
		os.Setenv("CI_JOB_JWT_V2", "token") //nolint:errcheck // test env setup

		cfg := &config.Config{CloudEnabled: true}
		assert.False(t, shouldSubmitToCloud(cfg, false, true))
	})

	t.Run("--no-cloud beats --cloud", func(t *testing.T) {
		os.Setenv("CI_JOB_JWT_V2", "token") //nolint:errcheck // test env setup

		cfg := &config.Config{CloudEnabled: true}
		assert.False(t, shouldSubmitToCloud(cfg, true, true))
	})

	t.Run("OIDC available auto-enables cloud", func(t *testing.T) {
		os.Setenv("CI_JOB_JWT_V2", "token") //nolint:errcheck // test env setup

		cfg := &config.Config{CloudEnabled: false}
		assert.True(t, shouldSubmitToCloud(cfg, false, false))
	})

	t.Run("OIDC available with --cloud flag", func(t *testing.T) {
		os.Setenv("CI_JOB_JWT_V2", "token") //nolint:errcheck // test env setup

		cfg := &config.Config{CloudEnabled: false}
		assert.True(t, shouldSubmitToCloud(cfg, true, false))
	})
}
