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
	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/cloud"
	"github.com/sigcomply/sigcomply-cli/internal/core/config"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

func TestBuildAttestation(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		PolicyResults: []evidence.PolicyResult{
			{PolicyID: "soc2-cc6.1-mfa", ControlID: "CC6.1", Status: evidence.StatusPass},
		},
	}
	checkResult.CalculateSummary()

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
		Storage: config.StorageConfig{
			Enabled: true,
			Backend: "local",
			Path:    "./.sigcomply/evidence",
		},
	}

	manifest := &storage.Manifest{
		RunID:         "run-123",
		Framework:     "soc2",
		Timestamp:     time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		EvidenceCount: 2,
		Items: []storage.StoredItem{
			{
				Path: "runs/soc2/2026-01-17/10-00-00/cc6.1-mfa/evidence/iam-users.json",
				Hash: "evidencehash1",
				Metadata: map[string]string{
					"resource_type": "aws:iam:user",
				},
			},
			{
				Path: "runs/soc2/2026-01-17/10-00-00/cc6.1-mfa/result.json",
				Hash: "resulthash1",
				Metadata: map[string]string{
					"type":      "policy_result",
					"policy_id": "soc2-cc6.1-mfa",
				},
			},
			{
				Path: "runs/soc2/2026-01-17/10-00-00/check_result.json",
				Hash: "checkresulthash1",
				Metadata: map[string]string{
					"type": "check_result",
				},
			},
			{
				Path: "runs/soc2/2026-01-17/10-00-00/manifest.json",
				Hash: "abc123hash",
				Metadata: map[string]string{
					"type":   "manifest",
					"run_id": "run-123",
				},
			},
		},
	}

	att, err := buildAttestation(cfg, checkResult, manifest)
	require.NoError(t, err)

	assert.NotEmpty(t, att.ID)
	assert.Equal(t, "run-123", att.RunID)
	assert.Equal(t, "soc2", att.Framework)
	assert.NotEmpty(t, att.Hashes.CheckResult)
	assert.NotEmpty(t, att.Hashes.Combined)
	// 3 stored files (evidence, result, check_result) — manifest is excluded
	assert.Len(t, att.Hashes.StoredFiles, 3)

	// OIDC-only: no HMAC signature
	assert.Empty(t, att.Signature.Algorithm)
	assert.Empty(t, att.Signature.Value)
}

func TestBuildAttestation_WithCIEnvironment(t *testing.T) {
	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	checkResult := &evidence.CheckResult{
		RunID:     "run-456",
		Framework: "soc2",
		Timestamp: ts,
	}

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
		CI:           true,
		CIProvider:   "github-actions",
		Repository:   "owner/repo",
		Branch:       "main",
		CommitSHA:    "abc123def",
	}

	manifest := &storage.Manifest{
		RunID:     "run-456",
		Framework: "soc2",
		Timestamp: ts,
		Items: []storage.StoredItem{
			{Path: "runs/soc2/2026-02-14/18-20-49/check_result.json", Hash: "crhash", Metadata: map[string]string{"type": "check_result"}},
			{Path: "runs/soc2/2026-02-14/18-20-49/manifest.json", Hash: "mhash", Metadata: map[string]string{"type": "manifest"}},
		},
	}

	att, err := buildAttestation(cfg, checkResult, manifest)
	require.NoError(t, err)

	assert.True(t, att.Environment.CI)
	assert.Equal(t, "github-actions", att.Environment.Provider)
	assert.Equal(t, "owner/repo", att.Environment.Repository)
	assert.Equal(t, "main", att.Environment.Branch)
	assert.Equal(t, "abc123def", att.Environment.CommitSHA)
}

func TestBuildAttestation_WithStorageLocation(t *testing.T) {
	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	checkResult := &evidence.CheckResult{
		RunID:     "run-789",
		Framework: "soc2",
		Timestamp: ts,
	}

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
		Storage: config.StorageConfig{
			Enabled: true,
			Backend: "s3",
			Bucket:  "my-evidence-bucket",
			Prefix:  "compliance/",
		},
	}

	manifest := &storage.Manifest{
		RunID:     "run-789",
		Framework: "soc2",
		Timestamp: ts,
		Items: []storage.StoredItem{
			{
				Path: "compliance/runs/soc2/2026-02-14/18-20-49/check_result.json",
				Hash: "crhash789",
				Metadata: map[string]string{
					"type": "check_result",
				},
			},
			{
				Path: "compliance/runs/soc2/2026-02-14/18-20-49/manifest.json",
				Hash: "manifesthash789",
				Metadata: map[string]string{
					"type":   "manifest",
					"run_id": "run-789",
				},
			},
		},
	}

	att, err := buildAttestation(cfg, checkResult, manifest)
	require.NoError(t, err)

	assert.Equal(t, "s3", att.StorageLocation.Backend)
	assert.Equal(t, "my-evidence-bucket", att.StorageLocation.Bucket)
	assert.Equal(t, "compliance/", att.StorageLocation.Path)
	assert.Equal(t, "compliance/runs/soc2/2026-02-14/18-20-49/manifest.json", att.StorageLocation.ManifestPath)
}

func TestBuildCloudSubmitRequest(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{PolicyID: "soc2-cc6.1-mfa", ControlID: "CC6.1", Status: evidence.StatusFail},
		},
	}
	checkResult.CalculateSummary()

	att := &attestation.Attestation{
		ID:        "attest-123",
		RunID:     "run-123",
		Framework: "soc2",
	}

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
		CI:           true,
		CIProvider:   "github-actions",
		Repository:   "owner/repo",
		Branch:       "main",
		CommitSHA:    "abc123",
		Storage: config.StorageConfig{
			Enabled: true,
			Backend: "s3",
			Bucket:  "my-bucket",
			Prefix:  "evidence/",
		},
	}

	manifest := &storage.Manifest{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC),
		Items: []storage.StoredItem{
			{
				Path: "evidence/runs/soc2/2026-02-14/18-20-49/manifest.json",
				Hash: "manifesthash",
				Metadata: map[string]string{
					"type":   "manifest",
					"run_id": "run-123",
				},
			},
		},
	}

	req := buildCloudSubmitRequest(cfg, checkResult, att, manifest)

	// Check result should be sanitized (same content for this test, no error statuses)
	assert.NotNil(t, req.CheckResult)
	assert.Equal(t, "run-123", req.CheckResult.RunID)
	assert.Equal(t, att, req.Attestation)

	// Check EvidenceLocation has all required fields for Rails
	assert.Equal(t, "s3", req.EvidenceLocation.Backend)
	assert.Equal(t, "my-bucket", req.EvidenceLocation.Bucket)
	assert.Equal(t, "evidence/", req.EvidenceLocation.Path)
	assert.Equal(t, "s3://my-bucket/evidence/", req.EvidenceLocation.URL)
	assert.Equal(t, "evidence/runs/soc2/2026-02-14/18-20-49/manifest.json", req.EvidenceLocation.ManifestPath)

	assert.True(t, req.RunMetadata.CI)
	assert.Equal(t, "github-actions", req.RunMetadata.CIProvider)
}

func TestBuildCloudSubmitRequest_LocalStorage(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "run-456",
		Framework: "soc2",
		Timestamp: time.Now(),
	}

	att := &attestation.Attestation{
		ID:    "attest-456",
		RunID: "run-456",
	}

	cfg := &config.Config{
		Framework: "soc2",
		Storage: config.StorageConfig{
			Enabled: true,
			Backend: "local",
			Path:    "/var/sigcomply/evidence",
		},
	}

	manifest := &storage.Manifest{
		RunID:     "run-456",
		Framework: "soc2",
		Timestamp: time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC),
		Items: []storage.StoredItem{
			{
				Path: "runs/soc2/2026-02-14/18-20-49/manifest.json",
				Hash: "manifesthashlocal",
				Metadata: map[string]string{
					"type":   "manifest",
					"run_id": "run-456",
				},
			},
		},
	}

	req := buildCloudSubmitRequest(cfg, checkResult, att, manifest)

	assert.Equal(t, "local", req.EvidenceLocation.Backend)
	assert.Equal(t, "/var/sigcomply/evidence", req.EvidenceLocation.Path)
	assert.Equal(t, "file:///var/sigcomply/evidence", req.EvidenceLocation.URL)
	assert.Equal(t, "/var/sigcomply/evidence/runs/soc2/2026-02-14/18-20-49/manifest.json", req.EvidenceLocation.ManifestPath)
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

		// Verify the request body has all required fields
		var req cloud.SubmitRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.NotNil(t, req.CheckResult)
		assert.NotNil(t, req.Attestation)

		// Return response in the Rails API format (nested structure)
		resp := cloud.SubmitResponse{
			Data: &cloud.SubmitResponseData{
				Run: &cloud.RunResponseData{
					ID:                 "run-123",
					AttestationID:      456,
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

	manifest := &storage.Manifest{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: ts,
		Items: []storage.StoredItem{
			{Path: "runs/soc2/2026-02-14/18-20-49/check_result.json", Hash: "crhash", Metadata: map[string]string{"type": "check_result"}},
			{Path: "runs/soc2/2026-02-14/18-20-49/manifest.json", Hash: "mhash", Metadata: map[string]string{"type": "manifest"}},
		},
	}

	resp, err := submitToCloud(context.Background(), cfg, checkResult, manifest, server.URL)
	require.NoError(t, err)

	// Use convenience methods to access the nested response
	assert.True(t, resp.Success())
	assert.Equal(t, "run-123", resp.RunID())

	// Also verify direct access works
	require.NotNil(t, resp.Data)
	require.NotNil(t, resp.Data.Run)
	assert.Equal(t, int64(456), resp.Data.Run.AttestationID)
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
	os.Unsetenv("CI_JOB_JWT_V2")              //nolint:errcheck // test env setup
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

	resp, err := submitToCloud(context.Background(), cfg, checkResult, nil, "")
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

	resp, err := submitToCloud(context.Background(), cfg, checkResult, nil, server.URL)
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

	resp, err := submitToCloud(context.Background(), cfg, checkResult, nil, server.URL)
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
		os.Unsetenv("CI_JOB_JWT_V2")              //nolint:errcheck // test env setup
		os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL") //nolint:errcheck // test env setup

		cfg := &config.Config{CloudEnabled: true}
		assert.False(t, shouldSubmitToCloud(cfg, false, false))
	})

	t.Run("no OIDC with --cloud flag still returns false", func(t *testing.T) {
		os.Unsetenv("CI_JOB_JWT_V2")              //nolint:errcheck // test env setup
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

func TestSanitizeCheckResultForCloud(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := sanitizeCheckResultForCloud(nil)
		assert.Nil(t, result)
	})

	t.Run("no error statuses unchanged", func(t *testing.T) {
		checkResult := &evidence.CheckResult{
			RunID:     "run-123",
			Framework: "soc2",
			Timestamp: time.Now(),
			PolicyResults: []evidence.PolicyResult{
				{PolicyID: "policy-1", Status: evidence.StatusPass, Message: "Passed"},
				{PolicyID: "policy-2", Status: evidence.StatusFail, Message: "Failed"},
				{PolicyID: "policy-3", Status: evidence.StatusSkip, Message: "Skipped"},
			},
		}
		checkResult.CalculateSummary()

		sanitized := sanitizeCheckResultForCloud(checkResult)

		assert.Equal(t, "run-123", sanitized.RunID)
		require.Len(t, sanitized.PolicyResults, 3)
		assert.Equal(t, evidence.StatusPass, sanitized.PolicyResults[0].Status)
		assert.Equal(t, "Passed", sanitized.PolicyResults[0].Message)
		assert.Equal(t, evidence.StatusFail, sanitized.PolicyResults[1].Status)
		assert.Equal(t, "Failed", sanitized.PolicyResults[1].Message)
		assert.Equal(t, evidence.StatusSkip, sanitized.PolicyResults[2].Status)
	})

	t.Run("error status mapped to fail", func(t *testing.T) {
		checkResult := &evidence.CheckResult{
			RunID:     "run-456",
			Framework: "soc2",
			Timestamp: time.Now(),
			PolicyResults: []evidence.PolicyResult{
				{PolicyID: "policy-1", Status: evidence.StatusPass, Message: "Passed"},
				{PolicyID: "policy-2", Status: evidence.StatusError, Message: "Connection timeout"},
				{PolicyID: "policy-3", Status: evidence.StatusError, Message: ""},
			},
		}
		checkResult.CalculateSummary()

		sanitized := sanitizeCheckResultForCloud(checkResult)

		require.Len(t, sanitized.PolicyResults, 3)

		// First policy unchanged
		assert.Equal(t, evidence.StatusPass, sanitized.PolicyResults[0].Status)
		assert.Equal(t, "Passed", sanitized.PolicyResults[0].Message)

		// Error with message -> Fail with prefixed message
		assert.Equal(t, evidence.StatusFail, sanitized.PolicyResults[1].Status)
		assert.Equal(t, "[Error during evaluation] Connection timeout", sanitized.PolicyResults[1].Message)

		// Error without message -> Fail with indicator
		assert.Equal(t, evidence.StatusFail, sanitized.PolicyResults[2].Status)
		assert.Equal(t, "[Error during evaluation]", sanitized.PolicyResults[2].Message)
	})

	t.Run("summary recalculated after sanitization", func(t *testing.T) {
		checkResult := &evidence.CheckResult{
			RunID:     "run-789",
			Framework: "soc2",
			Timestamp: time.Now(),
			PolicyResults: []evidence.PolicyResult{
				{PolicyID: "policy-1", Status: evidence.StatusPass},
				{PolicyID: "policy-2", Status: evidence.StatusError},
			},
		}
		checkResult.CalculateSummary()

		sanitized := sanitizeCheckResultForCloud(checkResult)

		// After sanitization, error becomes fail
		assert.Equal(t, 2, sanitized.Summary.TotalPolicies)
		assert.Equal(t, 1, sanitized.Summary.PassedPolicies)
		assert.Equal(t, 1, sanitized.Summary.FailedPolicies)
		assert.Equal(t, 0, sanitized.Summary.SkippedPolicies)
		assert.Equal(t, 0.5, sanitized.Summary.ComplianceScore)
	})

	t.Run("original unchanged", func(t *testing.T) {
		checkResult := &evidence.CheckResult{
			RunID:     "run-orig",
			Framework: "soc2",
			Timestamp: time.Now(),
			PolicyResults: []evidence.PolicyResult{
				{PolicyID: "policy-1", Status: evidence.StatusError, Message: "Original error"},
			},
		}
		checkResult.CalculateSummary()

		_ = sanitizeCheckResultForCloud(checkResult)

		// Original should remain unchanged
		assert.Equal(t, evidence.StatusError, checkResult.PolicyResults[0].Status)
		assert.Equal(t, "Original error", checkResult.PolicyResults[0].Message)
	})
}

func TestBuildEvidenceURL(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		bucket   string
		path     string
		expected string
	}{
		{
			name:     "s3 with bucket and path",
			backend:  "s3",
			bucket:   "my-bucket",
			path:     "evidence/path",
			expected: "s3://my-bucket/evidence/path",
		},
		{
			name:     "s3 with bucket only",
			backend:  "s3",
			bucket:   "my-bucket",
			path:     "",
			expected: "s3://my-bucket",
		},
		{
			name:     "s3 without bucket",
			backend:  "s3",
			bucket:   "",
			path:     "evidence/path",
			expected: "",
		},
		{
			name:     "gcs with bucket and path",
			backend:  "gcs",
			bucket:   "my-gcs-bucket",
			path:     "compliance/",
			expected: "gs://my-gcs-bucket/compliance/",
		},
		{
			name:     "gcs with bucket only",
			backend:  "gcs",
			bucket:   "my-gcs-bucket",
			path:     "",
			expected: "gs://my-gcs-bucket",
		},
		{
			name:     "local with path",
			backend:  "local",
			bucket:   "",
			path:     "/var/sigcomply/evidence",
			expected: "file:///var/sigcomply/evidence",
		},
		{
			name:     "local without path",
			backend:  "local",
			bucket:   "",
			path:     "",
			expected: "",
		},
		{
			name:     "unknown backend",
			backend:  "azure",
			bucket:   "container",
			path:     "path",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildEvidenceURL(tt.backend, tt.bucket, tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
