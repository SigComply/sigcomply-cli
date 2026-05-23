package core

import (
	"encoding/json"
	"time"
)

// EvidenceType is a versioned evidence-shape schema. The Schema is a
// JSON Schema document; collected records are validated against it
// before being wrapped in an Envelope.
type EvidenceType struct {
	ID      string
	Version int
	Schema  json.RawMessage
}

// EvidenceRecord is one observation produced by a source plugin.
// IdentityKey is set only when the evidence type has a meaningful
// cross-source identity (e.g. an email for user_record across
// aws.iam and okta); leaving it empty disables cross-source dedup.
type EvidenceRecord struct {
	Type        string
	ID          string
	IdentityKey string
	Payload     json.RawMessage
	SourceID    string
	CollectedAt time.Time
}
