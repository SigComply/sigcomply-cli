package sign

import (
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// manifestForSigning is the canonical shape of the signed manifest
// payload: every Manifest field except Signature. A verifier
// reconstructs this shape from a parsed manifest to recompute the
// bytes that were signed.
type manifestForSigning struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         string            `json:"run_id"`
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   time.Time         `json:"completed_at"`
	FileHashes    map[string]string `json:"file_hashes"`
}

// Manifest signs m in place using a fresh ephemeral Ed25519 keypair.
// The signature covers canonical JSON of every Manifest field except
// Signature itself — including FileHashes, which is the single-level
// Merkle root binding every file in the run folder.
func Manifest(m *core.Manifest) error {
	if m == nil {
		return fmt.Errorf("sign: nil manifest")
	}
	payload, err := manifestSigningBytes(m)
	if err != nil {
		return fmt.Errorf("sign manifest: %w", err)
	}
	sig, err := Sign(payload)
	if err != nil {
		return fmt.Errorf("sign manifest: %w", err)
	}
	m.Signature = core.ManifestSignature{
		Algorithm: sig.Algorithm,
		PublicKey: sig.PublicKey,
		Value:     sig.Value,
	}
	return nil
}

// VerifyManifest checks the embedded signature against m's content
// fields. Returns nil if valid.
func VerifyManifest(m *core.Manifest) error {
	if m == nil {
		return fmt.Errorf("sign: nil manifest")
	}
	payload, err := manifestSigningBytes(m)
	if err != nil {
		return fmt.Errorf("verify manifest: %w", err)
	}
	return Verify(payload, Signature{
		Algorithm: m.Signature.Algorithm,
		PublicKey: m.Signature.PublicKey,
		Value:     m.Signature.Value,
	})
}

// EncodeManifest returns the canonical JSON bytes of m (signature
// included). Returns an error if m has not been signed.
func EncodeManifest(m *core.Manifest) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("sign: nil manifest")
	}
	if len(m.Signature.Value) == 0 {
		return nil, fmt.Errorf("sign: manifest has no signature; call Manifest first")
	}
	return Encode(m)
}

func manifestSigningBytes(m *core.Manifest) ([]byte, error) {
	return Encode(manifestForSigning{
		SchemaVersion: m.SchemaVersion,
		RunID:         m.RunID,
		StartedAt:     m.StartedAt,
		CompletedAt:   m.CompletedAt,
		FileHashes:    m.FileHashes,
	})
}
