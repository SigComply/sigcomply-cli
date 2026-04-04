package manual

import "time"

// SubmittedEvidence is the JSON file downloaded from the React SPA and uploaded to storage.
type SubmittedEvidence struct {
	SchemaVersion   string                  `json:"schema_version"`
	EvidenceID      string                  `json:"evidence_id"`
	Type            EvidenceType            `json:"type"`
	Framework       string                  `json:"framework"`
	Control         string                  `json:"control"`
	Period          string                  `json:"period"` // "2026-Q1", "2026", "2026-03"
	CompletedBy     string                  `json:"completed_by"`
	CompletedAt     time.Time               `json:"completed_at"`
	Items           []SubmittedChecklistItem `json:"items,omitempty"`
	DeclarationText string                  `json:"declaration_text,omitempty"`
	Accepted        *bool                   `json:"accepted,omitempty"`
	Attachments     []string                `json:"attachments,omitempty"`
}

// SubmittedChecklistItem represents a completed checklist item.
type SubmittedChecklistItem struct {
	ID      string `json:"id"`
	Checked bool   `json:"checked"`
	Notes   string `json:"notes,omitempty"`
}
