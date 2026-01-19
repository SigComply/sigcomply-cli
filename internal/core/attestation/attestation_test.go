package attestation

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

func TestHashData(t *testing.T) {
	data := []byte("hello world")
	hash := HashData(data)

	// SHA-256 of "hello world" is known
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	assert.Equal(t, expected, hash)
}

func TestHashData_Empty(t *testing.T) {
	hash := HashData([]byte{})
	// SHA-256 of empty string
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	assert.Equal(t, expected, hash)
}

func TestHashData_Deterministic(t *testing.T) {
	data := []byte("test data")
	hash1 := HashData(data)
	hash2 := HashData(data)
	assert.Equal(t, hash1, hash2)
}

func TestHashJSON(t *testing.T) {
	data := map[string]string{"key": "value"}

	hash, err := HashJSON(data)
	require.NoError(t, err)
	assert.Len(t, hash, 64) // SHA-256 produces 64 hex characters
}

func TestHashCheckResult(t *testing.T) {
	result := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:  "soc2-cc6.1-mfa",
				ControlID: "CC6.1",
				Status:    evidence.StatusPass,
			},
		},
	}
	result.CalculateSummary()

	hash, err := HashCheckResult(result)
	require.NoError(t, err)
	assert.Len(t, hash, 64)

	// Should be deterministic
	hash2, err := HashCheckResult(result)
	require.NoError(t, err)
	assert.Equal(t, hash, hash2)
}

func TestHashCheckResult_DeterministicWithMaps(t *testing.T) {
	// This test ensures that CheckResult hashing is deterministic
	// even when Violations contain map[string]interface{} Details
	result := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:  "soc2-cc6.1-mfa",
				ControlID: "CC6.1",
				Status:    evidence.StatusFail,
				Violations: []evidence.Violation{
					{
						ResourceID:   "user-alice",
						ResourceType: "aws:iam:user",
						Reason:       "MFA not enabled",
						Details: map[string]interface{}{
							"z_field": "last",
							"a_field": "first",
							"m_field": map[string]interface{}{
								"nested_z": "z",
								"nested_a": "a",
							},
						},
					},
				},
			},
		},
	}
	result.CalculateSummary()

	// Hash multiple times - should always be identical
	var hashes []string
	for i := 0; i < 100; i++ {
		hash, err := HashCheckResult(result)
		require.NoError(t, err)
		hashes = append(hashes, hash)
	}

	for i := 1; i < len(hashes); i++ {
		assert.Equal(t, hashes[0], hashes[i], "Hash iteration %d differs", i)
	}
}

func TestHashEvidence(t *testing.T) {
	ev := evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", []byte(`{"user":"alice"}`))

	hash := HashEvidence(&ev)
	assert.NotEmpty(t, hash)
	assert.Equal(t, ev.Hash, hash) // Should use pre-computed hash
}

func TestComputeEvidenceHashes(t *testing.T) {
	result := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{PolicyID: "policy1", Status: evidence.StatusPass},
		},
	}
	result.CalculateSummary()

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "user1", []byte(`{"name":"alice"}`)),
		evidence.New("aws", "aws:iam:user", "user2", []byte(`{"name":"bob"}`)),
	}

	hashes, err := ComputeEvidenceHashes(result, evidenceList)
	require.NoError(t, err)

	assert.NotEmpty(t, hashes.CheckResult)
	assert.Len(t, hashes.Evidence, 2)
	assert.NotEmpty(t, hashes.Combined)

	// All evidence should be present
	for _, ev := range evidenceList {
		_, ok := hashes.Evidence[ev.ID]
		assert.True(t, ok)
	}
}

func TestComputeEvidenceHashes_Deterministic(t *testing.T) {
	result := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
	}

	// Same evidence IDs but different order
	ev1 := evidence.New("aws", "aws:iam:user", "user1", []byte(`{"name":"alice"}`))
	ev2 := evidence.New("aws", "aws:iam:user", "user2", []byte(`{"name":"bob"}`))

	hashes1, err := ComputeEvidenceHashes(result, []evidence.Evidence{ev1, ev2})
	require.NoError(t, err)

	hashes2, err := ComputeEvidenceHashes(result, []evidence.Evidence{ev2, ev1})
	require.NoError(t, err)

	// Combined hash should be the same regardless of order
	assert.Equal(t, hashes1.Combined, hashes2.Combined)
}

func TestVerifyHash(t *testing.T) {
	data := []byte("test data")
	hash := HashData(data)

	assert.True(t, VerifyHash(data, hash))
	assert.False(t, VerifyHash([]byte("different data"), hash))
}

func TestVerifyEvidenceHash(t *testing.T) {
	ev := evidence.New("aws", "aws:iam:user", "user1", []byte(`{"name":"alice"}`))
	assert.True(t, VerifyEvidenceHash(&ev))

	// Tamper with the data
	ev.Data = []byte(`{"name":"bob"}`)
	assert.False(t, VerifyEvidenceHash(&ev))
}

func TestHMACSigner_Sign(t *testing.T) {
	secret := []byte("test-secret-key")
	signer := NewHMACSigner(secret)

	attestation := &Attestation{
		ID:        "attest-123",
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
		Hashes: EvidenceHashes{
			CheckResult: "abc123",
			Combined:    "def456",
		},
	}

	err := signer.Sign(attestation)
	require.NoError(t, err)

	assert.Equal(t, AlgorithmHMACSHA256, attestation.Signature.Algorithm)
	assert.NotEmpty(t, attestation.Signature.Value)
	assert.Equal(t, "hmac-key", attestation.Signature.KeyID)
}

func TestHMACSigner_WithCustomKeyID(t *testing.T) {
	signer := NewHMACSignerWithKeyID([]byte("secret"), "my-key-id")

	attestation := &Attestation{
		ID:        "attest-123",
		Timestamp: time.Now(),
	}

	err := signer.Sign(attestation)
	require.NoError(t, err)
	assert.Equal(t, "my-key-id", attestation.Signature.KeyID)
}

func TestHMACVerifier_Verify(t *testing.T) {
	secret := []byte("test-secret-key")
	signer := NewHMACSigner(secret)
	verifier := NewHMACVerifier(secret)

	attestation := &Attestation{
		ID:        "attest-123",
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
		Hashes: EvidenceHashes{
			CheckResult: "abc123",
			Combined:    "def456",
		},
	}

	// Sign
	err := signer.Sign(attestation)
	require.NoError(t, err)

	// Verify
	err = verifier.Verify(attestation)
	assert.NoError(t, err)
}

func TestHMACVerifier_Verify_InvalidSignature(t *testing.T) {
	signer := NewHMACSigner([]byte("secret1"))
	verifier := NewHMACVerifier([]byte("secret2")) // Different secret

	attestation := &Attestation{
		ID:        "attest-123",
		Timestamp: time.Now(),
	}

	err := signer.Sign(attestation)
	require.NoError(t, err)

	err = verifier.Verify(attestation)
	require.Error(t, err)

	var sigErr *SignatureError
	assert.ErrorAs(t, err, &sigErr)
}

func TestHMACVerifier_Verify_TamperedData(t *testing.T) {
	secret := []byte("test-secret")
	signer := NewHMACSigner(secret)
	verifier := NewHMACVerifier(secret)

	attestation := &Attestation{
		ID:        "attest-123",
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
	}

	err := signer.Sign(attestation)
	require.NoError(t, err)

	// Tamper with data
	attestation.Framework = "hipaa"

	err = verifier.Verify(attestation)
	require.Error(t, err)
}

func TestHMACVerifier_Verify_WrongAlgorithm(t *testing.T) {
	verifier := NewHMACVerifier([]byte("secret"))

	attestation := &Attestation{
		ID:        "attest-123",
		Timestamp: time.Now(),
		Signature: Signature{
			Algorithm: "unknown-algo",
			Value:     "some-value",
		},
	}

	err := verifier.Verify(attestation)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signature algorithm")
}

func TestAttestation_Payload(t *testing.T) {
	attestation := &Attestation{
		ID:        "attest-123",
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		Hashes: EvidenceHashes{
			CheckResult: "abc123",
			Combined:    "def456",
		},
	}

	payload, err := attestation.Payload()
	require.NoError(t, err)

	// Should be valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(payload, &parsed)
	require.NoError(t, err)

	// Should not contain signature
	_, hasSignature := parsed["signature"]
	assert.False(t, hasSignature)

	// Should contain other fields
	assert.Equal(t, "attest-123", parsed["id"])
	assert.Equal(t, "soc2", parsed["framework"])
}

func TestAttestation_Payload_ExcludesStorageLocation(t *testing.T) {
	// StorageLocation should NOT be in the signed payload
	// because it's operational metadata that may change
	attestation := &Attestation{
		ID:        "attest-123",
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		Hashes: EvidenceHashes{
			CheckResult: "abc123",
			Combined:    "def456",
		},
		StorageLocation: StorageLocation{
			Backend: "s3",
			Bucket:  "my-bucket",
			Path:    "evidence/",
		},
	}

	payload, err := attestation.Payload()
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(payload, &parsed)
	require.NoError(t, err)

	// StorageLocation should NOT be in the payload
	_, hasStorageLocation := parsed["storage_location"]
	assert.False(t, hasStorageLocation, "storage_location should not be in signed payload")

	// Verify that changing storage location doesn't change the payload
	attestation2 := *attestation
	attestation2.StorageLocation = StorageLocation{
		Backend: "gcs",
		Bucket:  "different-bucket",
		Path:    "different/path/",
	}

	payload2, err := attestation2.Payload()
	require.NoError(t, err)

	assert.Equal(t, string(payload), string(payload2), "changing storage location should not change payload")
}

func TestAttestation_Payload_IncludesVersionInfo(t *testing.T) {
	attestation := &Attestation{
		ID:        "attest-123",
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		Hashes: EvidenceHashes{
			CheckResult: "abc123",
			Combined:    "def456",
		},
		CLIVersion: "1.2.3",
		PolicyVersions: map[string]string{
			"soc2-cc6.1-mfa":        "abc123",
			"soc2-cc6.2-encryption": "def456",
		},
	}

	payload, err := attestation.Payload()
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(payload, &parsed)
	require.NoError(t, err)

	// CLIVersion should be in payload
	assert.Equal(t, "1.2.3", parsed["cli_version"])

	// PolicyVersions should be in payload
	policyVersions, ok := parsed["policy_versions"].(map[string]interface{})
	require.True(t, ok, "policy_versions should be a map")
	assert.Equal(t, "abc123", policyVersions["soc2-cc6.1-mfa"])
	assert.Equal(t, "def456", policyVersions["soc2-cc6.2-encryption"])
}

func TestAttestation_Payload_Deterministic(t *testing.T) {
	// Payload should be deterministic even with maps
	attestation := &Attestation{
		ID:        "attest-123",
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		Hashes: EvidenceHashes{
			CheckResult: "abc123",
			Evidence: map[string]string{
				"z_evidence": "hash_z",
				"a_evidence": "hash_a",
				"m_evidence": "hash_m",
			},
			Combined: "def456",
		},
		PolicyVersions: map[string]string{
			"z_policy": "version_z",
			"a_policy": "version_a",
			"m_policy": "version_m",
		},
	}

	// Generate payload multiple times - should always be identical
	var payloads []string
	for i := 0; i < 100; i++ {
		payload, err := attestation.Payload()
		require.NoError(t, err)
		payloads = append(payloads, string(payload))
	}

	for i := 1; i < len(payloads); i++ {
		assert.Equal(t, payloads[0], payloads[i], "Payload iteration %d differs", i)
	}
}

func TestAttestation_MarshalJSON(t *testing.T) {
	attestation := &Attestation{
		ID:        "attest-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(attestation)
	require.NoError(t, err)

	// Timestamp should be RFC3339 formatted
	assert.Contains(t, string(data), "2026-01-17T10:00:00Z")
}

func TestSignerAlgorithm(t *testing.T) {
	signer := NewHMACSigner([]byte("secret"))
	assert.Equal(t, AlgorithmHMACSHA256, signer.Algorithm())
}

// Test helper functions for env var management
// These suppress errcheck warnings as env var operations in tests are best-effort

func setEnv(key, value string) {
	_ = os.Setenv(key, value) //nolint:errcheck // Test helper, error not critical
}

func unsetEnv(key string) {
	_ = os.Unsetenv(key) //nolint:errcheck // Test helper, error not critical
}

// OIDC Signer Tests

func TestOIDCSigner_Sign(t *testing.T) {
	token := &OIDCToken{
		Token:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
		Provider: ProviderGitHubActions,
		Issuer:   "https://token.actions.githubusercontent.com",
	}
	signer := NewOIDCSigner(token)

	attestation := &Attestation{
		ID:        "attest-123",
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
		Hashes: EvidenceHashes{
			CheckResult: "abc123",
			Combined:    "def456",
		},
	}

	err := signer.Sign(attestation)
	require.NoError(t, err)

	assert.Equal(t, AlgorithmOIDCJWT, attestation.Signature.Algorithm)
	assert.Equal(t, token.Token, attestation.Signature.Value)
	assert.Equal(t, "github-actions", attestation.Signature.KeyID)
}

func TestOIDCSigner_Algorithm(t *testing.T) {
	signer := NewOIDCSigner(&OIDCToken{Token: "test"})
	assert.Equal(t, AlgorithmOIDCJWT, signer.Algorithm())
}

func TestOIDCSigner_Sign_NilToken(t *testing.T) {
	signer := NewOIDCSigner(nil)

	attestation := &Attestation{
		ID:        "attest-123",
		Timestamp: time.Now(),
	}

	err := signer.Sign(attestation)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC token is required")
}

func TestOIDCSigner_Sign_EmptyToken(t *testing.T) {
	signer := NewOIDCSigner(&OIDCToken{Token: ""})

	attestation := &Attestation{
		ID:        "attest-123",
		Timestamp: time.Now(),
	}

	err := signer.Sign(attestation)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC token is required")
}

func TestOIDCSigner_WithGitLabProvider(t *testing.T) {
	token := &OIDCToken{
		Token:    "gitlab-jwt-token",
		Provider: ProviderGitLabCI,
		Issuer:   "https://gitlab.com",
	}
	signer := NewOIDCSigner(token)

	attestation := &Attestation{
		ID:        "attest-456",
		Timestamp: time.Now(),
	}

	err := signer.Sign(attestation)
	require.NoError(t, err)

	assert.Equal(t, AlgorithmOIDCJWT, attestation.Signature.Algorithm)
	assert.Equal(t, "gitlab-jwt-token", attestation.Signature.Value)
	assert.Equal(t, "gitlab-ci", attestation.Signature.KeyID)
}

func TestDetectOIDCProvider_NoProvider(t *testing.T) {
	// Save and restore original values
	originalGH := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalGL := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalGH != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGH)
		}
		if originalGL != "" {
			setEnv("CI_JOB_JWT_V2", originalGL)
		}
	})

	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	unsetEnv("CI_JOB_JWT_V2")

	provider := DetectOIDCProvider()
	assert.Equal(t, ProviderUnknown, provider)
}

func TestDetectOIDCProvider_GitHubActions(t *testing.T) {
	original := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	t.Cleanup(func() {
		if original != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", original)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
	})

	setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.githubusercontent.com")

	provider := DetectOIDCProvider()
	assert.Equal(t, ProviderGitHubActions, provider)
}

func TestDetectOIDCProvider_GitLabCI(t *testing.T) {
	// Clear GitHub Actions first
	originalGH := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalGL := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalGH != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGH)
		}
		if originalGL != "" {
			setEnv("CI_JOB_JWT_V2", originalGL)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	setEnv("CI_JOB_JWT_V2", "some-jwt-token")

	provider := DetectOIDCProvider()
	assert.Equal(t, ProviderGitLabCI, provider)
}

func TestGitHubActionsTokenProvider_Available(t *testing.T) {
	originalURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	t.Cleanup(func() {
		if originalURL != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalURL)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
		if originalToken != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", originalToken)
		} else {
			unsetEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		}
	})

	provider := NewGitHubActionsTokenProvider()

	// Not available when env vars are not set
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	assert.False(t, provider.Available())

	// Available when both env vars are set
	setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com")
	setEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "token123")
	assert.True(t, provider.Available())
}

func TestGitLabCITokenProvider_Available(t *testing.T) {
	original := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if original != "" {
			setEnv("CI_JOB_JWT_V2", original)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	provider := NewGitLabCITokenProvider()

	unsetEnv("CI_JOB_JWT_V2")
	assert.False(t, provider.Available())

	setEnv("CI_JOB_JWT_V2", "jwt-token")
	assert.True(t, provider.Available())
}

func TestGitLabCITokenProvider_GetToken(t *testing.T) {
	originalJWT := os.Getenv("CI_JOB_JWT_V2")
	originalURL := os.Getenv("CI_SERVER_URL")
	t.Cleanup(func() {
		if originalJWT != "" {
			setEnv("CI_JOB_JWT_V2", originalJWT)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
		if originalURL != "" {
			setEnv("CI_SERVER_URL", originalURL)
		} else {
			unsetEnv("CI_SERVER_URL")
		}
	})

	ctx := context.Background()
	provider := NewGitLabCITokenProvider()

	// Test when token is set
	setEnv("CI_JOB_JWT_V2", "test-jwt-token")
	setEnv("CI_SERVER_URL", "https://gitlab.example.com")

	token, err := provider.GetToken(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, "test-jwt-token", token.Token)
	assert.Equal(t, ProviderGitLabCI, token.Provider)
	assert.Equal(t, "https://gitlab.example.com", token.Issuer)
}

func TestGitLabCITokenProvider_GetToken_NotSet(t *testing.T) {
	original := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if original != "" {
			setEnv("CI_JOB_JWT_V2", original)
		} else {
			unsetEnv("CI_JOB_JWT_V2")
		}
	})

	unsetEnv("CI_JOB_JWT_V2")

	ctx := context.Background()
	provider := NewGitLabCITokenProvider()

	token, err := provider.GetToken(ctx, "")
	require.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "CI_JOB_JWT_V2 not set")
}

func TestGetOIDCTokenProvider_NoProvider(t *testing.T) {
	originalGH := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalGL := os.Getenv("CI_JOB_JWT_V2")
	t.Cleanup(func() {
		if originalGH != "" {
			setEnv("ACTIONS_ID_TOKEN_REQUEST_URL", originalGH)
		}
		if originalGL != "" {
			setEnv("CI_JOB_JWT_V2", originalGL)
		}
	})

	unsetEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	unsetEnv("CI_JOB_JWT_V2")

	provider := GetOIDCTokenProvider()
	assert.Nil(t, provider)
}

func TestOIDCProviderConstants(t *testing.T) {
	assert.Equal(t, OIDCProvider("github-actions"), ProviderGitHubActions)
	assert.Equal(t, OIDCProvider("gitlab-ci"), ProviderGitLabCI)
	assert.Equal(t, OIDCProvider("unknown"), ProviderUnknown)
}
