package core

import (
	"encoding/json"
	"time"
)

// EvidenceType is a versioned evidence-shape schema. The Schema is a
// JSON Schema document; collected records are validated against it
// before being wrapped in an Envelope.
type EvidenceType struct {
	ID      string          `json:"id"`
	Version int             `json:"version"`
	Schema  json.RawMessage `json:"schema"`
}

// EvidenceRecord is one observation produced by a source plugin.
// IdentityKey is set only when the evidence type has a meaningful
// cross-source identity (e.g. an email for user_record across
// aws.iam and okta); leaving it empty disables cross-source dedup.
type EvidenceRecord struct {
	Type        string          `json:"type"`
	ID          string          `json:"id"`
	IdentityKey string          `json:"identity_key,omitempty"`
	Payload     json.RawMessage `json:"payload"`
	SourceID    string          `json:"source_id"`
	CollectedAt time.Time       `json:"collected_at"`
	// Scope records which account/region/project this observation was
	// collected from. Sovereignty buyers are multi-account/multi-region
	// by regulatory necessity (data residency), so an auditor reading a
	// single envelope has to be able to tell which account it describes.
	//
	// Provenance only — NOT a dimension of identity. Nothing reads this
	// field: no collector, evaluator, aggregator or report branches on
	// it, and the pass_when DSL cannot reach it (getField resolves id,
	// type, source_id, payload.* and account.*, but no scope.*). Record
	// dedup is the clause IdentityKey, defaulting to ID, so two records
	// with the same ID and different Scope collapse into one — the
	// opposite of what a reader might assume. Scope as a per-record
	// dimension of identity is deferred to v2 along with multi-scope
	// projects; see docs/architecture/04-source-plugins.md §"Record
	// scope: provenance, not configuration" and 01-conceptual-model.md.
	//
	// Optional and pointer-typed so records that don't set it serialize
	// byte-identically to pre-scope envelopes (no signature churn);
	// source plugins populate it incrementally as they gain
	// scope-awareness, so most records carry nil today. Scope stays
	// vault-side — it never crosses the aggregation boundary into the
	// Cloud SubmissionPayload.
	Scope *RecordScope `json:"scope,omitempty"`
}

// RecordScope is the account/region/project an EvidenceRecord was
// collected from. Every field is omitempty so a partially-known scope
// (e.g. region but no project) still serializes minimally. The names
// are deliberately cloud-neutral: Account covers an AWS account ID, a
// GCP project number, an Azure subscription, or an Okta org; Region
// covers any geographic locality; Project covers a finer subdivision
// (GCP project ID, Azure resource group) when one applies.
type RecordScope struct {
	Account string `json:"account,omitempty"`
	Region  string `json:"region,omitempty"`
	Project string `json:"project,omitempty"`
}
