package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestVerifyHash(t *testing.T) {
	data := []byte("test data")
	hash := HashData(data)

	assert.True(t, VerifyHash(data, hash))
	assert.False(t, VerifyHash([]byte("different data"), hash))
}

func TestNewEvidenceEnvelope(t *testing.T) {
	ts := time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC)
	evidenceData := json.RawMessage(`[{"resource_id":"alice","mfa":true}]`)

	e := NewEvidenceEnvelope(ts, evidenceData)

	require.NotNil(t, e)
	assert.Equal(t, ts, e.Signed.Timestamp)
	assert.Equal(t, string(evidenceData), string(e.Signed.Evidence))
	assert.Empty(t, e.PublicKey, "PublicKey should be empty before signing")
	assert.Empty(t, e.Signature.Value, "Signature should be empty before signing")
}

func TestNewEd25519Signer_Success(t *testing.T) {
	signer, err := NewEd25519Signer()
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestEd25519Signer_Algorithm(t *testing.T) {
	signer, err := NewEd25519Signer()
	require.NoError(t, err)
	assert.Equal(t, AlgorithmEd25519, signer.Algorithm())
}

func TestEd25519Signer_Sign(t *testing.T) {
	signer, err := NewEd25519Signer()
	require.NoError(t, err)

	e := NewEvidenceEnvelope(
		time.Now(),
		json.RawMessage(`[{"resource_id":"alice","mfa":true}]`),
	)

	err = signer.Sign(e)
	require.NoError(t, err)

	assert.Equal(t, AlgorithmEd25519, e.Signature.Algorithm)
	assert.NotEmpty(t, e.Signature.Value)
	assert.NotEmpty(t, e.PublicKey)
}

func TestEd25519Signer_Sign_SetsPublicKey(t *testing.T) {
	signer, err := NewEd25519Signer()
	require.NoError(t, err)

	e := NewEvidenceEnvelope(time.Now(), json.RawMessage(`{}`))
	err = signer.Sign(e)
	require.NoError(t, err)

	// PublicKey should be base64-encoded 32-byte Ed25519 public key
	pubKeyBytes, decodeErr := base64.StdEncoding.DecodeString(e.PublicKey)
	require.NoError(t, decodeErr)
	assert.Len(t, pubKeyBytes, 32, "Ed25519 public key should be 32 bytes")
}

func TestEd25519Signer_Sign_UniqueKeysPerSigner(t *testing.T) {
	signer1, err := NewEd25519Signer()
	require.NoError(t, err)
	signer2, err := NewEd25519Signer()
	require.NoError(t, err)

	e1 := NewEvidenceEnvelope(time.Now(), json.RawMessage(`[{"id":"1"}]`))
	e2 := NewEvidenceEnvelope(time.Now(), json.RawMessage(`[{"id":"2"}]`))

	require.NoError(t, signer1.Sign(e1))
	require.NoError(t, signer2.Sign(e2))

	// Each signer generates a unique keypair
	assert.NotEqual(t, e1.PublicKey, e2.PublicKey, "Each signer should have a unique public key")
}

func TestEd25519Verifier_Verify(t *testing.T) {
	signer, err := NewEd25519Signer()
	require.NoError(t, err)
	verifier := NewEd25519Verifier()

	e := NewEvidenceEnvelope(
		time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		json.RawMessage(`[{"resource_id":"alice","mfa":true}]`),
	)

	err = signer.Sign(e)
	require.NoError(t, err)

	err = verifier.Verify(e)
	assert.NoError(t, err)
}

func TestEd25519Verifier_Verify_TamperedEvidence(t *testing.T) {
	signer, err := NewEd25519Signer()
	require.NoError(t, err)
	verifier := NewEd25519Verifier()

	e := NewEvidenceEnvelope(
		time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		json.RawMessage(`[{"resource_id":"alice","mfa":true}]`),
	)

	err = signer.Sign(e)
	require.NoError(t, err)

	// Tamper with evidence after signing
	e.Signed.Evidence = json.RawMessage(`[{"resource_id":"alice","mfa":false}]`)

	err = verifier.Verify(e)
	require.Error(t, err)

	var sigErr *SignatureError
	assert.ErrorAs(t, err, &sigErr)
}

func TestEd25519Verifier_Verify_TamperedTimestamp(t *testing.T) {
	signer, err := NewEd25519Signer()
	require.NoError(t, err)
	verifier := NewEd25519Verifier()

	e := NewEvidenceEnvelope(
		time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		json.RawMessage(`[{"resource_id":"alice","mfa":true}]`),
	)

	err = signer.Sign(e)
	require.NoError(t, err)

	// Tamper with timestamp after signing
	e.Signed.Timestamp = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	err = verifier.Verify(e)
	require.Error(t, err)

	var sigErr *SignatureError
	assert.ErrorAs(t, err, &sigErr)
}

func TestEd25519Verifier_Verify_WrongAlgorithm(t *testing.T) {
	verifier := NewEd25519Verifier()

	e := &EvidenceEnvelope{
		Signed: SignedPayload{
			Timestamp: time.Now(),
			Evidence:  json.RawMessage(`{}`),
		},
		PublicKey: "c29tZWtleQ==",
		Signature: Signature{
			Algorithm: "unknown-algo",
			Value:     "c29tZS12YWx1ZQ==",
		},
	}

	err := verifier.Verify(e)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signature algorithm")
}

func TestEd25519Verifier_Verify_InvalidPublicKey(t *testing.T) {
	verifier := NewEd25519Verifier()

	e := &EvidenceEnvelope{
		Signed: SignedPayload{
			Timestamp: time.Now(),
			Evidence:  json.RawMessage(`{}`),
		},
		PublicKey: "not-valid-base64!!!",
		Signature: Signature{
			Algorithm: AlgorithmEd25519,
			Value:     "c29tZS12YWx1ZQ==",
		},
	}

	err := verifier.Verify(e)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode public key")
}

func TestSignedPayload_CanonicalJSON_Deterministic(t *testing.T) {
	// Same payload marshaled 100 times should always produce identical bytes.
	// This is critical for cryptographic signing.
	e := NewEvidenceEnvelope(
		time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		json.RawMessage(`{"z_key":"z_val","a_key":"a_val","m_key":{"nested_z":1,"nested_a":2}}`),
	)

	var payloads [][]byte
	for i := 0; i < 100; i++ {
		p, err := CanonicalJSON(e.Signed)
		require.NoError(t, err)
		payloads = append(payloads, p)
	}

	for i := 1; i < len(payloads); i++ {
		assert.Equal(t, string(payloads[0]), string(payloads[i]),
			"CanonicalJSON iteration %d differs from iteration 0", i)
	}
}

// Test helper functions for env var management
// These suppress errcheck warnings as env var operations in tests are best-effort

func setEnv(key, value string) {
	_ = os.Setenv(key, value) //nolint:errcheck // Test helper, error not critical
}

func unsetEnv(key string) {
	_ = os.Unsetenv(key) //nolint:errcheck // Test helper, error not critical
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
