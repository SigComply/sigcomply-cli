// Package attestation provides per-file signed envelopes for compliance evidence.
package attestation

import (
	"encoding/json"
	"time"
)

// EvidenceEnvelope is the on-disk format for every evidence file stored in customer S3.
// Each file is independently verifiable: an auditor can pick any single file and verify
// its integrity without needing any other artifact or contacting SigComply.
//
// The Signed field contains the payload covered by the signature. PublicKey and Signature
// are stored alongside it but are not included in the signed bytes.
type EvidenceEnvelope struct {
	// Signed is the payload covered by the cryptographic signature.
	Signed SignedPayload `json:"signed"`

	// PublicKey is the base64-encoded Ed25519 public key used to sign this file.
	// The corresponding private key was discarded immediately after signing.
	PublicKey string `json:"public_key"`

	// Signature contains the cryptographic signature over Signed.
	Signature Signature `json:"signature"`
}

// SignedPayload is the tamper-evident core of an EvidenceEnvelope.
// This is exactly what gets signed: canonical JSON of this struct.
// Adding or removing fields here changes what is covered by the signature.
type SignedPayload struct {
	// Timestamp is when the evidence was collected.
	// Proves the evidence falls within the audit period.
	// S3 object mtimes can be modified; this timestamp cannot be changed
	// without invalidating the signature.
	Timestamp time.Time `json:"timestamp"`

	// Evidence is the raw API response data collected from the source service.
	Evidence json.RawMessage `json:"evidence"`
}

// Signature contains the cryptographic signature value and algorithm identifier.
type Signature struct {
	// Algorithm is the signing algorithm. Currently "ed25519".
	Algorithm string `json:"algorithm"`

	// Value is the base64-encoded signature bytes.
	Value string `json:"value"`
}

// AlgorithmEd25519 is the algorithm identifier for Ed25519 signatures.
const AlgorithmEd25519 = "ed25519"

// NewEvidenceEnvelope creates a new EvidenceEnvelope with the signed payload populated.
// Call Sign on the returned envelope to add PublicKey and Signature.
func NewEvidenceEnvelope(timestamp time.Time, evidenceData json.RawMessage) *EvidenceEnvelope {
	return &EvidenceEnvelope{
		Signed: SignedPayload{
			Timestamp: timestamp,
			Evidence:  evidenceData,
		},
	}
}
