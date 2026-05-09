package storage

// ManualSidecar carries the user-supplied evidence.pdf for one manual evidence
// entry, so that StoreRun can mirror it into each referencing policy's run
// folder under manual_attachments/{evidence_id}/evidence.pdf alongside the
// signed envelope. ResourceType matches Evidence.ResourceType ("manual:<id>")
// so the storage layer can find which policy folders referenced this entry.
//
// FileHash is the SHA-256 of the PDF bytes in hex. It is recorded in the
// framework summary and the per-run signed manifest, and surfaced for auditor
// verification (the auditor re-hashes the mirrored PDF and compares).
type ManualSidecar struct {
	EvidenceID   string
	Period       string
	ResourceType string
	PDF          []byte
	FileHash     string
}
