// Package manual provides types and logic for manual evidence collection.
//
// Architectural note — manual evidence is exactly one PDF per (evidence_id,
// period) at {framework}/{evidence_id}/{period}/{EvidencePDFFilename} in the
// configured manual-evidence storage prefix. The CLI reads the PDF, hashes
// the bytes, and runs the policy. It does not parse the PDF in v1.
//
// The catalog YAML still carries Type, Items, DeclarationText, and
// AcceptedFormats. These are descriptive hints — most useful to the optional
// Evidence SPA helper when it renders a clickable form for declaration- or
// checklist-style entries. The CLI never branches on them at evaluation time,
// and they are irrelevant for evidence the user produces outside the SPA
// (HR exports, scanned documents, training certificates, etc.).
package manual

// EvidenceType is a descriptive hint, not a CLI evaluation discriminator.
//
// It describes the shape of the evidence (free-form upload vs. declaration vs.
// checklist) and is most useful to the optional Evidence SPA helper when it
// decides whether to render an interactive form. The CLI ignores this field —
// every manual evidence flows through the same PDF presence + temporal-window
// check regardless of type.
type EvidenceType string

// Evidence type constants describe the shape of a manual evidence entry.
// document_upload entries have no clickable form (the user produces the PDF
// externally — e.g. exported from an HR system, scanned, or downloaded from
// a third-party tool — and uploads it directly to the storage path).
const (
	EvidenceTypeDocumentUpload EvidenceType = "document_upload"
	EvidenceTypeChecklist      EvidenceType = "checklist"
	EvidenceTypeDeclaration    EvidenceType = "declaration"
)

// Frequency represents how often manual evidence must be provided.
type Frequency string

// Frequency constants define how often manual evidence must be collected.
const (
	FrequencyDaily     Frequency = "daily"
	FrequencyWeekly    Frequency = "weekly"
	FrequencyMonthly   Frequency = "monthly"
	FrequencyQuarterly Frequency = "quarterly"
	FrequencyYearly    Frequency = "yearly"
)

// TemporalRule controls when evidence can be uploaded relative to the period.
type TemporalRule string

// TemporalRule constants control when evidence may be uploaded relative to the collection period.
const (
	TemporalRuleRetrospective TemporalRule = "retrospective"
	TemporalRuleAnytime       TemporalRule = "anytime"
)

// CatalogEntry defines a single manual evidence requirement.
type CatalogEntry struct {
	ID              string          `yaml:"id" json:"id"`
	Control         string          `yaml:"control" json:"control"`
	Type            EvidenceType    `yaml:"type" json:"type"`
	Frequency       Frequency       `yaml:"frequency" json:"frequency"`
	TemporalRule    TemporalRule    `yaml:"temporal_rule" json:"temporal_rule"`
	GracePeriod     string          `yaml:"grace_period" json:"grace_period"` // "15d", "30d"
	Name            string          `yaml:"name" json:"name"`
	Description     string          `yaml:"description" json:"description"`
	Severity        string          `yaml:"severity" json:"severity"`
	AcceptedFormats []string        `yaml:"accepted_formats,omitempty" json:"accepted_formats,omitempty"`
	Items           []ChecklistItem `yaml:"items,omitempty" json:"items,omitempty"`
	DeclarationText string          `yaml:"declaration_text,omitempty" json:"declaration_text,omitempty"`
	Category        string          `yaml:"category,omitempty" json:"category,omitempty"`
	TSC             string          `yaml:"tsc,omitempty" json:"tsc,omitempty"`
	Optional        bool            `yaml:"optional,omitempty" json:"optional,omitempty"`

	// PathTemplate optionally overrides where the CLI looks for the
	// evidence PDF. Defaults to "{framework}/{evidence_id}/{period}/{filename}".
	// Supported placeholders: {framework}, {evidence_id}, {period}, {year},
	// {quarter}, {month}, {filename}. {quarter} and {month} are only valid
	// for the matching frequency.
	PathTemplate string `yaml:"path_template,omitempty" json:"path_template,omitempty"`

	// Filename overrides the expected PDF filename. Defaults to "evidence.pdf".
	// Must end in ".pdf" in v1.
	Filename string `yaml:"filename,omitempty" json:"filename,omitempty"`
}

// ChecklistItem defines a single item in a checklist-type evidence entry.
type ChecklistItem struct {
	ID       string `yaml:"id" json:"id"`
	Text     string `yaml:"text" json:"text"`
	Required bool   `yaml:"required" json:"required"`
}

// Catalog holds the full set of manual evidence requirements for a framework.
type Catalog struct {
	Framework string         `yaml:"framework" json:"framework"`
	Version   string         `yaml:"version" json:"version"`
	Entries   []CatalogEntry `yaml:"entries" json:"entries"`
}

// GetEntry returns the catalog entry with the given ID, or nil if not found.
func (c *Catalog) GetEntry(id string) *CatalogEntry {
	for i := range c.Entries {
		if c.Entries[i].ID == id {
			return &c.Entries[i]
		}
	}
	return nil
}

// EntriesForControl returns all catalog entries for a given control ID.
func (c *Catalog) EntriesForControl(controlID string) []CatalogEntry {
	var result []CatalogEntry
	for i := range c.Entries {
		if c.Entries[i].Control == controlID {
			result = append(result, c.Entries[i])
		}
	}
	return result
}
