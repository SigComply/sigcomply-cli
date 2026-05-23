package sign

import (
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// envelopeForSigning is the canonical shape of the signed payload:
// the envelope's three content fields, no signature. A verifier
// reconstructs this exact shape from a parsed envelope to recompute
// the bytes the signer signed.
type envelopeForSigning struct {
	FormatVersion string                `json:"format_version"`
	ProducedAt    time.Time             `json:"produced_at"`
	Records       []core.EvidenceRecord `json:"records"`
}

// Envelope signs e in place. After return, e.Signature carries the
// ephemeral keypair's public key and the signature value. The
// signature covers canonical JSON of {format_version, produced_at,
// records} — three fields, no signature sentinel.
func Envelope(e *core.Envelope) error {
	if e == nil {
		return fmt.Errorf("sign: nil envelope")
	}
	payload, err := envelopeSigningBytes(e)
	if err != nil {
		return fmt.Errorf("sign envelope: %w", err)
	}
	sig, err := Sign(payload)
	if err != nil {
		return fmt.Errorf("sign envelope: %w", err)
	}
	e.Signature = core.EnvelopeSignature{
		Algorithm: sig.Algorithm,
		PublicKey: sig.PublicKey,
		Value:     sig.Value,
	}
	return nil
}

// VerifyEnvelope checks the embedded signature against the envelope's
// content fields. Returns nil if the signature is valid.
func VerifyEnvelope(e *core.Envelope) error {
	if e == nil {
		return fmt.Errorf("sign: nil envelope")
	}
	payload, err := envelopeSigningBytes(e)
	if err != nil {
		return fmt.Errorf("verify envelope: %w", err)
	}
	return Verify(payload, Signature{
		Algorithm: e.Signature.Algorithm,
		PublicKey: e.Signature.PublicKey,
		Value:     e.Signature.Value,
	})
}

// EncodeEnvelope returns the canonical JSON bytes of e (signature
// included). This is the form written to the vault: the on-disk bytes
// are byte-identical across writers, so an auditor can verify by
// either re-canonicalizing on read or checking the file's SHA-256
// against a recorded hash.
//
// Returns an error if e has not been signed.
func EncodeEnvelope(e *core.Envelope) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("sign: nil envelope")
	}
	if len(e.Signature.Value) == 0 {
		return nil, fmt.Errorf("sign: envelope has no signature; call Envelope first")
	}
	return Encode(e)
}

func envelopeSigningBytes(e *core.Envelope) ([]byte, error) {
	return Encode(envelopeForSigning{
		FormatVersion: e.FormatVersion,
		ProducedAt:    e.ProducedAt,
		Records:       e.Records,
	})
}
