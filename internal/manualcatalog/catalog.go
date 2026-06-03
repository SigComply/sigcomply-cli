// Package manualcatalog defines the descriptive, presentation-facing
// manual-evidence catalog that `sigcomply evidence catalog` exports as
// JSON. It is the contract the optional Evidence SPA builds against
// (its scripts/fetch-catalogs.ts consumes this exact shape).
//
// This is metadata only. The CLI evaluator never branches on Type,
// Items, or DeclarationText — every manual policy flows through the same
// PDF-presence check regardless (see Invariant #2 in CLAUDE.md). These
// fields exist so the SPA can render a clickable form for declaration-
// and checklist-style entries; document_upload entries are produced
// externally and the SPA filters them out. Keeping the catalog here —
// derived from each framework's manual policies — preserves a single
// source of truth: the framework owns both the policy and its catalog
// metadata, and they cannot drift.
package manualcatalog

// EvidenceType is a descriptive hint about an entry's shape, NOT a CLI
// evaluation discriminator. The SPA renders a form for checklist and
// declaration entries; document_upload entries are produced outside the
// SPA and filtered from its dashboard.
type EvidenceType string

// Evidence type values. document_upload entries are produced outside the
// SPA; checklist and declaration entries render as SPA forms.
const (
	TypeDocumentUpload EvidenceType = "document_upload"
	TypeChecklist      EvidenceType = "checklist"
	TypeDeclaration    EvidenceType = "declaration"
)

// Frequency mirrors the SPA's Frequency union. Note the CLI cadence DSL
// uses "annual"; the export maps it to "yearly" to match the SPA.
type Frequency string

// Frequency values mirroring the SPA's Frequency union.
const (
	FrequencyDaily     Frequency = "daily"
	FrequencyWeekly    Frequency = "weekly"
	FrequencyMonthly   Frequency = "monthly"
	FrequencyQuarterly Frequency = "quarterly"
	FrequencyYearly    Frequency = "yearly"
)

// TemporalRule controls when evidence may be uploaded relative to the
// period. Manual policies are retrospective today.
type TemporalRule string

// Temporal rule values controlling upload timing relative to the period.
const (
	TemporalRetrospective TemporalRule = "retrospective"
	TemporalAnytime       TemporalRule = "anytime"
)

// ChecklistItem is one row of a checklist-type entry's form.
type ChecklistItem struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Required bool   `json:"required"`
}

// Entry is one manual-evidence requirement, in the shape the SPA's
// CatalogEntry type expects. Field order and json tags match
// sigcomply-evidence-spa/src/types/catalog.ts exactly.
type Entry struct {
	ID              string          `json:"id"`
	Control         string          `json:"control"`
	Type            EvidenceType    `json:"type"`
	Frequency       Frequency       `json:"frequency"`
	TemporalRule    TemporalRule    `json:"temporal_rule"`
	GracePeriod     string          `json:"grace_period"` // "15d", "30d"
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Severity        string          `json:"severity"`
	AcceptedFormats []string        `json:"accepted_formats,omitempty"`
	Items           []ChecklistItem `json:"items,omitempty"`
	DeclarationText string          `json:"declaration_text,omitempty"`
	Category        string          `json:"category,omitempty"`
	TSC             string          `json:"tsc,omitempty"`
	Optional        bool            `json:"optional,omitempty"`
}

// Catalog is the top-level export: framework id, a version string, and
// the entries. Matches the SPA's Catalog type.
type Catalog struct {
	Framework string  `json:"framework"`
	Version   string  `json:"version"`
	Entries   []Entry `json:"entries"`
}
