package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Signer defines the interface for signing evidence envelopes.
type Signer interface {
	// Sign signs the envelope, populating PublicKey and Signature fields.
	Sign(e *EvidenceEnvelope) error

	// Algorithm returns the signing algorithm identifier.
	Algorithm() string
}

// Verifier defines the interface for verifying evidence envelope signatures.
type Verifier interface {
	// Verify verifies the signature on an envelope using the embedded public key.
	Verify(e *EvidenceEnvelope) error
}

// Ed25519Signer signs evidence envelopes using an ephemeral Ed25519 keypair.
// A fresh keypair is generated once by NewEd25519Signer. The private key is zeroed
// immediately after Sign returns and should not be used again.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewEd25519Signer creates a new signer with a freshly generated ephemeral Ed25519 keypair.
// Call Sign exactly once; the private key is zeroed after signing.
func NewEd25519Signer() (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}
	return &Ed25519Signer{
		privateKey: priv,
		publicKey:  pub,
	}, nil
}

// Algorithm returns the signing algorithm identifier.
func (s *Ed25519Signer) Algorithm() string {
	return AlgorithmEd25519
}

// Sign signs the canonical JSON of the envelope's Signed payload with the ephemeral Ed25519 private key.
// It sets e.PublicKey (base64-encoded Ed25519 public key bytes) and e.Signature.
// The private key bytes are zeroed immediately after signing.
func (s *Ed25519Signer) Sign(e *EvidenceEnvelope) error {
	payload, err := CanonicalJSON(e.Signed)
	if err != nil {
		return fmt.Errorf("failed to serialize signed payload: %w", err)
	}

	sig := ed25519.Sign(s.privateKey, payload)

	e.PublicKey = base64.StdEncoding.EncodeToString(s.publicKey)
	e.Signature = Signature{
		Algorithm: AlgorithmEd25519,
		Value:     base64.StdEncoding.EncodeToString(sig),
	}

	// Zero the private key immediately — it must never be stored or reused.
	for i := range s.privateKey {
		s.privateKey[i] = 0
	}

	return nil
}

// Ed25519Verifier verifies Ed25519 signatures on evidence envelopes.
// The public key is read from the envelope's PublicKey field.
type Ed25519Verifier struct{}

// NewEd25519Verifier creates a new verifier.
func NewEd25519Verifier() *Ed25519Verifier {
	return &Ed25519Verifier{}
}

// Verify verifies the Ed25519 signature on an envelope using its embedded public key.
func (v *Ed25519Verifier) Verify(e *EvidenceEnvelope) error {
	if e.Signature.Algorithm != AlgorithmEd25519 {
		return fmt.Errorf("unsupported signature algorithm: %s", e.Signature.Algorithm)
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length: got %d, want %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(e.Signature.Value)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	payload, err := CanonicalJSON(e.Signed)
	if err != nil {
		return fmt.Errorf("failed to serialize signed payload: %w", err)
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)
	if !ed25519.Verify(pubKey, payload, sigBytes) {
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
