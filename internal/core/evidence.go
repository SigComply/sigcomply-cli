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
	// by regulatory necessity (data residency), so scope is a
	// first-class dimension of evidence identity — two records with the
	// same ID but different Scope are distinct observations. Optional
	// and pointer-typed so records that don't set it serialize
	// byte-identically to pre-scope envelopes (no signature churn);
	// source plugins populate it incrementally as they gain
	// scope-awareness. Scope stays vault-side — it never crosses the
	// aggregation boundary into the Cloud SubmissionPayload.
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
