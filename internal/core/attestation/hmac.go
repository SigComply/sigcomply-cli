package attestation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Signer defines the interface for signing attestations.
type Signer interface {
	// Sign signs the attestation and populates the Signature field.
	Sign(attestation *Attestation) error

	// Algorithm returns the signing algorithm identifier.
	Algorithm() string
}

// Verifier defines the interface for verifying attestation signatures.
type Verifier interface {
	// Verify verifies the signature on an attestation.
	Verify(attestation *Attestation) error
}

// HMACSigner signs attestations using HMAC-SHA256.
type HMACSigner struct {
	secret []byte
	keyID  string
}

// NewHMACSigner creates a new HMAC signer with the given secret.
func NewHMACSigner(secret []byte) *HMACSigner {
	return &HMACSigner{
		secret: secret,
		keyID:  "hmac-key",
	}
}

// NewHMACSignerWithKeyID creates a new HMAC signer with a custom key ID.
func NewHMACSignerWithKeyID(secret []byte, keyID string) *HMACSigner {
	return &HMACSigner{
		secret: secret,
		keyID:  keyID,
	}
}

// Algorithm returns the signing algorithm identifier.
func (s *HMACSigner) Algorithm() string {
	return AlgorithmHMACSHA256
}

// Sign signs the attestation using HMAC-SHA256.
func (s *HMACSigner) Sign(attestation *Attestation) error {
	// Get the payload to sign
	payload, err := attestation.Payload()
	if err != nil {
		return fmt.Errorf("failed to get attestation payload: %w", err)
	}

	// Compute HMAC
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	signature := mac.Sum(nil)

	// Set signature on attestation
	attestation.Signature = Signature{
		Algorithm: AlgorithmHMACSHA256,
		Value:     base64.StdEncoding.EncodeToString(signature),
		KeyID:     s.keyID,
	}

	return nil
}

// HMACVerifier verifies HMAC-SHA256 signatures.
type HMACVerifier struct {
	secret []byte
}

// NewHMACVerifier creates a new HMAC verifier with the given secret.
func NewHMACVerifier(secret []byte) *HMACVerifier {
	return &HMACVerifier{
		secret: secret,
	}
}

// Verify verifies the HMAC-SHA256 signature on an attestation.
func (v *HMACVerifier) Verify(attestation *Attestation) error {
	// Check algorithm
	if attestation.Signature.Algorithm != AlgorithmHMACSHA256 {
		return fmt.Errorf("unsupported signature algorithm: %s", attestation.Signature.Algorithm)
	}

	// Decode the signature
	expectedSig, err := base64.StdEncoding.DecodeString(attestation.Signature.Value)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Get the payload
	payload, err := attestation.Payload()
	if err != nil {
		return fmt.Errorf("failed to get attestation payload: %w", err)
	}

	// Compute expected HMAC
	mac := hmac.New(sha256.New, v.secret)
	mac.Write(payload)
	actualSig := mac.Sum(nil)

	// Compare using constant-time comparison
	if !hmac.Equal(actualSig, expectedSig) {
		return &SignatureError{Message: "signature verification failed"}
	}

	return nil
}

// SignatureError represents a signature verification failure.
type SignatureError struct {
	Message string
}

func (e *SignatureError) Error() string {
	return "signature error: " + e.Message
}
