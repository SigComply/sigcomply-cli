package storage

// ManualSidecar carries the raw evidence.json a customer uploaded plus any
// supporting files (PDFs, screenshots) for one manual evidence entry, so that
// StoreRun can mirror them into the policy result bucket alongside the
// OPA-derived envelope. ResourceType matches Evidence.ResourceType ("manual:<id>")
// so we can find the policy folders that referenced this entry.
type ManualSidecar struct {
	EvidenceID   string
	Period       string
	ResourceType string
	EvidenceJSON []byte
	Attachments  map[string][]byte
}
