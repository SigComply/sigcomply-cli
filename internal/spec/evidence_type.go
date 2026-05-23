package spec

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// evidenceTypeHeader is the subset of the JSON Schema document that the
// loader inspects directly. The full bytes are preserved as the
// EvidenceType.Schema field for downstream validation (L4 / M6).
type evidenceTypeHeader struct {
	Schema  string `json:"$schema"`
	ID      string `json:"$id"`
	Title   string `json:"title"`
	Version int    `json:"version"`
	Type    string `json:"type"`
}

// LoadEvidenceType parses a JSON Schema document declaring an evidence
// type and returns the L1 core.EvidenceType. See
// docs/architecture/04-source-plugins.md §Evidence types for the
// canonical file shape.
//
// The Schema field on the returned value is the original bytes verbatim
// — record-against-schema validation happens at L4 (M6) using a JSON
// Schema library; this loader only checks the wrapper fields it needs.
func LoadEvidenceType(data []byte) (core.EvidenceType, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return core.EvidenceType{}, fmt.Errorf("evidence type spec: empty input")
	}
	var hdr evidenceTypeHeader
	if err := json.Unmarshal(data, &hdr); err != nil {
		return core.EvidenceType{}, fmt.Errorf("evidence type spec: parse: %w", err)
	}
	if hdr.Title == "" {
		return core.EvidenceType{}, fmt.Errorf("evidence type spec: missing required field \"title\"")
	}
	if hdr.Version <= 0 {
		return core.EvidenceType{}, fmt.Errorf("evidence type spec: %q: \"version\" must be a positive integer (got %d)", hdr.Title, hdr.Version)
	}
	if hdr.Type != "object" {
		return core.EvidenceType{}, fmt.Errorf("evidence type spec: %q: top-level \"type\" must be \"object\" (got %q)", hdr.Title, hdr.Type)
	}
	return core.EvidenceType{
		ID:      hdr.Title,
		Version: hdr.Version,
		Schema:  append(json.RawMessage(nil), data...),
	}, nil
}
