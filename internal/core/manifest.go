package core

import "time"

// Manifest is the per-run signed integrity root. A single Ed25519
// signature over FileHashes binds every file in the run folder; any
// later modification to a hashed file invalidates the manifest.
//
// M5 shipped the minimal shape sufficient to sign and round-trip;
// later milestones layer optional fields on top (framework + period
// for reporting/integrity, exceptions_applied for the exception
// register view). See docs/architecture/05-vault-layout.md §Per-run
// manifest.
type Manifest struct {
	SchemaVersion     string             `json:"schema_version"`
	RunID             string             `json:"run_id"`
	Framework         string             `json:"framework,omitempty"`
	PeriodID          string             `json:"period_id,omitempty"`
	StartedAt         time.Time          `json:"started_at"`
	CompletedAt       time.Time          `json:"completed_at"`
	FileHashes        map[string]string  `json:"file_hashes"`
	ExceptionsApplied []AppliedException `json:"exceptions_applied,omitempty"`
	Signature         ManifestSignature  `json:"signature"`
}

// AppliedException is the snapshot of a planner-resolved exception
// that was in effect for the run. The shape mirrors spec.ExceptionConfig
// in .sigcomply.yaml, plus the resolved state and policy ID so an
// auditor reading the manifest doesn't need the project config to
// reconstruct who waived what and why.
type AppliedException struct {
	PolicyID        string `json:"policy_id"`
	State           string `json:"state"`
	Reason          string `json:"reason,omitempty"`
	ApprovedBy      string `json:"approved_by,omitempty"`
	ApprovedAt      string `json:"approved_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	ResourceID      string `json:"resource_id,omitempty"`
	ResourcePattern string `json:"resource_pattern,omitempty"`
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
