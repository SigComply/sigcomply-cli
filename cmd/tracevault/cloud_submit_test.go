package tracevault

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
	"github.com/tracevault/tracevault-cli/internal/core/cloud"
	"github.com/tracevault/tracevault-cli/internal/core/config"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
	"github.com/tracevault/tracevault-cli/internal/core/storage"
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

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "user1", []byte(`{"name":"alice"}`)),
		evidence.New("aws", "aws:s3:bucket", "bucket1", []byte(`{"name":"test-bucket"}`)),
	}

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
		APIToken:     "test-token",
		Storage: config.StorageConfig{
			Enabled: true,
			Backend: "local",
			Path:    "./.tracevault/evidence",
		},
	}

	manifest := &storage.Manifest{
		RunID:         "run-123",
		EvidenceCount: 2,
		Items: []storage.StoredItem{
			{
				Path: "runs/run-123/manifest.json",
				Hash: "abc123hash",
				Metadata: map[string]string{
					"type":   "manifest",
					"run_id": "run-123",
				},
			},
		},
	}

	att, err := buildAttestation(cfg, checkResult, evidenceList, manifest)
	require.NoError(t, err)

	assert.NotEmpty(t, att.ID)
	assert.Equal(t, "run-123", att.RunID)
	assert.Equal(t, "soc2", att.Framework)
	assert.NotEmpty(t, att.Hashes.CheckResult)
	assert.NotEmpty(t, att.Hashes.Combined)
	assert.Len(t, att.Hashes.Evidence, 2)

	// Should have signature if API token is present
	assert.Equal(t, attestation.AlgorithmHMACSHA256, att.Signature.Algorithm)
	assert.NotEmpty(t, att.Signature.Value)
}

func TestBuildAttestation_WithCIEnvironment(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "run-456",
		Framework: "soc2",
		Timestamp: time.Now(),
	}

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
		APIToken:     "test-token",
		CI:           true,
		CIProvider:   "github-actions",
		Repository:   "owner/repo",
		Branch:       "main",
		CommitSHA:    "abc123def",
	}

	att, err := buildAttestation(cfg, checkResult, nil, nil)
	require.NoError(t, err)

	assert.True(t, att.Environment.CI)
	assert.Equal(t, "github-actions", att.Environment.Provider)
	assert.Equal(t, "owner/repo", att.Environment.Repository)
	assert.Equal(t, "main", att.Environment.Branch)
	assert.Equal(t, "abc123def", att.Environment.CommitSHA)
}

func TestBuildAttestation_WithStorageLocation(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "run-789",
		Framework: "soc2",
		Timestamp: time.Now(),
	}

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
		APIToken:     "test-token",
		Storage: config.StorageConfig{
			Enabled: true,
			Backend: "s3",
			Bucket:  "my-evidence-bucket",
			Prefix:  "compliance/",
		},
	}

	manifest := &storage.Manifest{
		RunID: "run-789",
		Items: []storage.StoredItem{
			{
				Path: "compliance/runs/run-789/manifest.json",
				Hash: "manifesthash789",
				Metadata: map[string]string{
					"type":   "manifest",
					"run_id": "run-789",
				},
			},
		},
	}

	att, err := buildAttestation(cfg, checkResult, nil, manifest)
	require.NoError(t, err)

	assert.Equal(t, "s3", att.StorageLocation.Backend)
	assert.Equal(t, "my-evidence-bucket", att.StorageLocation.Bucket)
	assert.Equal(t, "compliance/", att.StorageLocation.Prefix)
	assert.Equal(t, "compliance/runs/run-789/manifest.json", att.StorageLocation.ManifestPath)
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
		RunID: "run-123",
		Items: []storage.StoredItem{
			{
				Path: "evidence/runs/run-123/manifest.json",
				Hash: "manifesthash",
				Metadata: map[string]string{
					"type":   "manifest",
					"run_id": "run-123",
				},
			},
		},
	}

	req := buildCloudSubmitRequest(cfg, checkResult, att, manifest)

	assert.Equal(t, checkResult, req.CheckResult)
	assert.Equal(t, att, req.Attestation)
	assert.Equal(t, "s3", req.EvidenceLocation.Backend)
	assert.Equal(t, "my-bucket", req.EvidenceLocation.Path)
	assert.Equal(t, "evidence/runs/run-123/manifest.json", req.EvidenceLocation.ManifestPath)
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
			Path:    "/var/tracevault/evidence",
		},
	}

	manifest := &storage.Manifest{
		RunID: "run-456",
		Items: []storage.StoredItem{
			{
				Path: "/var/tracevault/evidence/runs/run-456/manifest.json",
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
	assert.Equal(t, "/var/tracevault/evidence", req.EvidenceLocation.Path)
	assert.Equal(t, "/var/tracevault/evidence/runs/run-456/manifest.json", req.EvidenceLocation.ManifestPath)
}

func TestSubmitToCloud_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/runs", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer test-token")

		// Verify the request body has all required fields
		var req cloud.SubmitRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.NotNil(t, req.CheckResult)
		assert.NotNil(t, req.Attestation)

		resp := cloud.SubmitResponse{
			Success:      true,
			RunID:        "run-123",
			Message:      "Submission accepted",
			DashboardURL: "https://app.tracevault.io/runs/run-123",
			DriftSummary: &cloud.DriftSummary{
				HasDrift:      true,
				NewViolations: 2,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // Test server
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
		APIToken:     "test-token",
	}

	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
	}

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "user1", []byte(`{"name":"alice"}`)),
	}

	resp, err := submitToCloud(context.Background(), cfg, checkResult, evidenceList, nil, server.URL)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.Equal(t, "run-123", resp.RunID)
	assert.True(t, resp.DriftSummary.HasDrift)
	assert.Equal(t, 2, resp.DriftSummary.NewViolations)
}

func TestSubmitToCloud_NotConfigured(t *testing.T) {
	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: false, // Cloud not enabled
	}

	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
	}

	resp, err := submitToCloud(context.Background(), cfg, checkResult, nil, nil, "")
	assert.Nil(t, resp)
	assert.NoError(t, err) // Should not error, just skip
}

func TestSubmitToCloud_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		//nolint:errcheck // Test server
		json.NewEncoder(w).Encode(map[string]string{
			"code":    "unauthorized",
			"message": "invalid token",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		Framework:    "soc2",
		CloudEnabled: true,
		APIToken:     "bad-token",
	}

	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
	}

	resp, err := submitToCloud(context.Background(), cfg, checkResult, nil, nil, server.URL)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestShouldSubmitToCloud(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		cloud    bool
		noCloud  bool
		expected bool
	}{
		{
			name:     "cloud enabled by config",
			cfg:      &config.Config{CloudEnabled: true, APIToken: "token"},
			expected: true,
		},
		{
			name:     "cloud disabled by config",
			cfg:      &config.Config{CloudEnabled: false},
			expected: false,
		},
		{
			name:     "force cloud via flag",
			cfg:      &config.Config{CloudEnabled: false, APIToken: "token"},
			cloud:    true,
			expected: true,
		},
		{
			name:     "disable cloud via flag",
			cfg:      &config.Config{CloudEnabled: true, APIToken: "token"},
			noCloud:  true,
			expected: false,
		},
		{
			name:     "no-cloud takes precedence over cloud",
			cfg:      &config.Config{CloudEnabled: true, APIToken: "token"},
			cloud:    true,
			noCloud:  true,
			expected: false,
		},
		{
			name:     "cloud enabled but no token",
			cfg:      &config.Config{CloudEnabled: true, APIToken: ""},
			expected: false,
		},
		{
			name:     "force cloud but no token",
			cfg:      &config.Config{CloudEnabled: false, APIToken: ""},
			cloud:    true,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSubmitToCloud(tt.cfg, tt.cloud, tt.noCloud)
			assert.Equal(t, tt.expected, result)
		})
	}
}
