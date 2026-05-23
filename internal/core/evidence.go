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
}
