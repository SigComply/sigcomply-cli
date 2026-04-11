// Package manual provides types and logic for manual evidence collection.
package manual

// EvidenceType represents the kind of manual evidence.
type EvidenceType string

const (
	EvidenceTypeDocumentUpload EvidenceType = "document_upload"
	EvidenceTypeChecklist      EvidenceType = "checklist"
	EvidenceTypeDeclaration    EvidenceType = "declaration"
)

// Frequency represents how often manual evidence must be provided.
type Frequency string

const (
	FrequencyDaily     Frequency = "daily"
	FrequencyWeekly    Frequency = "weekly"
	FrequencyMonthly   Frequency = "monthly"
	FrequencyQuarterly Frequency = "quarterly"
	FrequencyYearly    Frequency = "yearly"
)

// TemporalRule controls when evidence can be uploaded relative to the period.
type TemporalRule string

const (
	TemporalRuleRetrospective TemporalRule = "retrospective"
	TemporalRuleAnytime       TemporalRule = "anytime"
)

// CatalogEntry defines a single manual evidence requirement.
type CatalogEntry struct {
	ID              string        `yaml:"id" json:"id"`
	Control         string        `yaml:"control" json:"control"`
	Type            EvidenceType  `yaml:"type" json:"type"`
	Frequency       Frequency     `yaml:"frequency" json:"frequency"`
	TemporalRule    TemporalRule  `yaml:"temporal_rule" json:"temporal_rule"`
	GracePeriod     string        `yaml:"grace_period" json:"grace_period"` // "15d", "30d"
	Name            string        `yaml:"name" json:"name"`
	Description     string        `yaml:"description" json:"description"`
	Severity        string        `yaml:"severity" json:"severity"`
	AcceptedFormats []string      `yaml:"accepted_formats,omitempty" json:"accepted_formats,omitempty"`
	Items           []ChecklistItem `yaml:"items,omitempty" json:"items,omitempty"`
	DeclarationText string        `yaml:"declaration_text,omitempty" json:"declaration_text,omitempty"`
	Category        string        `yaml:"category,omitempty" json:"category,omitempty"`
	TSC             string        `yaml:"tsc,omitempty" json:"tsc,omitempty"`
	Optional        bool          `yaml:"optional,omitempty" json:"optional,omitempty"`
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
	for _, e := range c.Entries {
		if e.Control == controlID {
			result = append(result, e)
		}
	}
	return result
}
