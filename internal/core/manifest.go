package core

import "time"

// Manifest is the per-run signed integrity root. A single Ed25519
// signature over FileHashes binds every file in the run folder; any
// later modification to a hashed file invalidates the manifest.
//
// M5 ships the minimal shape sufficient to sign and round-trip. Later
// milestones add framework, period, CI environment, exceptions, and
// retention metadata as L4/L9 need them (see docs/architecture/05-
// vault-layout.md §Per-run manifest).
type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         string            `json:"run_id"`
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   time.Time         `json:"completed_at"`
	FileHashes    map[string]string `json:"file_hashes"`
	Signature     ManifestSignature `json:"signature"`
}

// ManifestSignature mirrors EnvelopeSignature: a fresh ephemeral
// Ed25519 keypair is generated at signing time, the private key is
// zeroed immediately, and the public key is embedded so the manifest
// is independently verifiable.
type ManifestSignature struct {
	Algorithm string `json:"algorithm"`
	PublicKey []byte `json:"public_key"`
	Value     []byte `json:"value"`
}
