// Package manual provides types and logic for manual evidence collection.
//
// Architectural note — manual evidence is exactly one PDF per (evidence_id,
// period) at {framework}/{evidence_id}/{period}/{EvidencePDFFilename} in the
// configured manual-evidence storage prefix. The CLI reads the PDF, hashes
// the bytes, and runs the policy. It does not parse the PDF in v1.
//
// The catalog YAML still carries Type, Items, DeclarationText, and
// AcceptedFormats — those are RENDER HINTS for the SigComply Evidence SPA
// when it presents a clickable form. The CLI never branches on them at
// evaluation time.
package manual

// EvidenceType is a render hint for the SPA, not a CLI evaluation discriminator.
//
// Catalog entries use one of the constants below to tell the SPA whether
// (and how) to render an interactive form for the entry. The CLI ignores
// this field — every manual evidence is the same PDF flow regardless of type.
type EvidenceType string

// Evidence type constants define how the SPA should render the form for an
// entry. document_upload entries are typically not rendered by the SPA at
// all (the user produces the PDF externally and uploads it directly).
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
