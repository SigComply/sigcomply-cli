package registry

import "github.com/sigcomply/sigcomply-cli/internal/core"

// NewEvidenceTypeRegistry returns an empty registry of
// core.EvidenceType keyed by ID. Evidence type schemas are
// append-only: a breaking schema change requires a new ID (e.g.
// user_record.v2 registered alongside user_record.v1).
func NewEvidenceTypeRegistry() *Registry[core.EvidenceType] {
	return New(func(t core.EvidenceType) string { return t.ID })
}
