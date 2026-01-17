package attestation

import (
	"encoding/json"
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
