// Package attestation provides cryptographic attestation for compliance evidence.
package attestation

import (
	"encoding/json"
	"time"
)

// Attestation represents a cryptographic attestation of compliance evidence.
type Attestation struct {
	// ID is the unique identifier for this attestation.
	ID string `json:"id"`

	// RunID links this attestation to a specific compliance check run.
	RunID string `json:"run_id"`

	// Framework is the compliance framework used.
	Framework string `json:"framework"`

	// Timestamp is when the attestation was created.
	Timestamp time.Time `json:"timestamp"`

	// Hashes contains cryptographic hashes of all evidence.
	Hashes EvidenceHashes `json:"hashes"`

	// Signature contains the cryptographic signature.
	Signature Signature `json:"signature"`

	// Environment captures context about where the check was executed.
	Environment Environment `json:"environment"`

	// StorageLocation references where evidence is stored.
	// NOTE: This field is NOT included in the signed payload.
	// It is operational metadata that may change (e.g., evidence migration)
	// without invalidating the attestation signature.
	StorageLocation StorageLocation `json:"storage_location"`

	// Version information for reproducibility.

	// CLIVersion is the version of the CLI that created this attestation.
	CLIVersion string `json:"cli_version,omitempty"`

	// PolicyVersions maps policy IDs to their version hashes.
	// This allows verification that the same policies were used.
	PolicyVersions map[string]string `json:"policy_versions,omitempty"`
}

// EvidenceHashes contains cryptographic hashes of evidence components.
type EvidenceHashes struct {
	// CheckResult is the SHA-256 hash of the check result JSON.
	CheckResult string `json:"check_result"`

	// Evidence maps evidence IDs to their SHA-256 hashes.
	Evidence map[string]string `json:"evidence"`

	// Manifest is the SHA-256 hash of the storage manifest.
	Manifest string `json:"manifest,omitempty"`

	// Combined is a single hash representing all evidence.
	Combined string `json:"combined"`
}

// Signature contains cryptographic signature information.
type Signature struct {
	// Algorithm is the signing algorithm used (hmac-sha256, oidc-jwt).
	Algorithm string `json:"algorithm"`

	// Value is the base64-encoded signature value.
	Value string `json:"value"`

	// KeyID identifies the key used for signing.
	KeyID string `json:"key_id,omitempty"`

	// Certificate contains the signing certificate (for OIDC).
	Certificate string `json:"certificate,omitempty"`
}

// Environment captures context about the execution environment.
type Environment struct {
	// CI indicates if running in a CI environment.
	CI bool `json:"ci"`

	// Provider is the CI provider (github-actions, gitlab-ci).
	Provider string `json:"provider,omitempty"`

	// Repository is the source repository.
	Repository string `json:"repository,omitempty"`

	// Branch is the git branch.
	Branch string `json:"branch,omitempty"`

	// CommitSHA is the git commit hash.
	CommitSHA string `json:"commit_sha,omitempty"`

	// WorkflowName is the CI workflow name.
	WorkflowName string `json:"workflow_name,omitempty"`

	// RunID is the CI run identifier.
	RunID string `json:"run_id,omitempty"`

	// Actor is the user/entity that triggered the run.
	Actor string `json:"actor,omitempty"`
}

// StorageLocation describes where evidence is stored.
// This structure is sent to the TraceVault Cloud API as part of attestations.
type StorageLocation struct {
	// Backend is the storage backend type (local, s3, gcs).
	Backend string `json:"backend"`

	// Bucket is the storage bucket (for cloud storage).
	Bucket string `json:"bucket,omitempty"`

	// Path is the key/path prefix where evidence is stored.
	// For S3: this is the prefix within the bucket.
	// For local: this is the directory path.
	Path string `json:"path,omitempty"`

	// ManifestPath is the path to the storage manifest.
	ManifestPath string `json:"manifest_path,omitempty"`

	// Encrypted indicates if the evidence is encrypted at rest.
	Encrypted bool `json:"encrypted,omitempty"`
}

// SigningAlgorithm constants.
const (
	AlgorithmHMACSHA256 = "hmac-sha256"
	AlgorithmOIDCJWT    = "oidc-jwt"
)

// MarshalJSON implements custom JSON marshaling.
func (a *Attestation) MarshalJSON() ([]byte, error) {
	type Alias Attestation
	return json.Marshal(&struct {
		*Alias
		Timestamp string `json:"timestamp"`
	}{
		Alias:     (*Alias)(a),
		Timestamp: a.Timestamp.Format(time.RFC3339),
	})
}

// Payload returns the data that should be signed.
// NOTE: StorageLocation is intentionally excluded from the signed payload.
// It is operational metadata that may change (e.g., evidence migration)
// without invalidating the cryptographic proof of the evidence itself.
func (a *Attestation) Payload() ([]byte, error) {
	// Create a copy without the signature and storage location for signing.
	// We use CanonicalJSON to ensure deterministic serialization,
	// especially for maps like PolicyVersions.
	payload := struct {
		ID             string            `json:"id"`
		RunID          string            `json:"run_id"`
		Framework      string            `json:"framework"`
		Timestamp      string            `json:"timestamp"`
		Hashes         EvidenceHashes    `json:"hashes"`
		Environment    Environment       `json:"environment"`
		CLIVersion     string            `json:"cli_version,omitempty"`
		PolicyVersions map[string]string `json:"policy_versions,omitempty"`
	}{
		ID:             a.ID,
		RunID:          a.RunID,
		Framework:      a.Framework,
		Timestamp:      a.Timestamp.Format(time.RFC3339),
		Hashes:         a.Hashes,
		Environment:    a.Environment,
		CLIVersion:     a.CLIVersion,
		PolicyVersions: a.PolicyVersions,
	}

	// Use canonical JSON for deterministic serialization
	return CanonicalJSON(payload)
}
