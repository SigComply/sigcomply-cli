package manual

// SubmittedEvidenceSchema returns a JSON Schema (as a map) describing the SubmittedEvidence type.
// This is the single source of truth — the SPA fetches this at build time to generate TypeScript types.
func SubmittedEvidenceSchema() map[string]interface{} {
	return map[string]interface{}{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"title":       "SubmittedEvidence",
		"description": "JSON file produced by the SigComply SPA and uploaded to storage for CLI evaluation.",
		"type":        "object",
		"required":    []string{"schema_version", "evidence_id", "type", "framework", "control", "period", "completed_by", "completed_at"},
		"properties": map[string]interface{}{
			"schema_version": map[string]interface{}{
				"type":        "string",
				"description": "Schema version for forward compatibility.",
				"enum":        []string{"1.0"},
			},
			"evidence_id": map[string]interface{}{
				"type":        "string",
				"description": "Matches a catalog entry ID (e.g., 'quarterly_access_review').",
			},
			"type": map[string]interface{}{
				"type":        "string",
				"description": "Evidence type — determines which optional fields are relevant.",
				"enum":        []string{string(EvidenceTypeDocumentUpload), string(EvidenceTypeChecklist), string(EvidenceTypeDeclaration)},
			},
			"framework": map[string]interface{}{
				"type":        "string",
				"description": "Compliance framework (e.g., 'soc2').",
			},
			"control": map[string]interface{}{
				"type":        "string",
				"description": "Control ID (e.g., 'CC6.1').",
			},
			"period": map[string]interface{}{
				"type":        "string",
				"description": "Evidence period key (e.g., '2026-Q1', '2026', '2026-03').",
			},
			"completed_by": map[string]interface{}{
				"type":        "string",
				"description": "Email or identifier of the person who completed this evidence.",
			},
			"completed_at": map[string]interface{}{
				"type":        "string",
				"format":      "date-time",
				"description": "ISO 8601 timestamp when evidence was completed.",
			},
			"items": map[string]interface{}{
				"type":        "array",
				"description": "Checklist items (only for type 'checklist').",
				"items": map[string]interface{}{
					"type":     "object",
					"required": []string{"id", "checked"},
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"type":        "string",
							"description": "Matches a checklist item ID from the catalog.",
						},
						"checked": map[string]interface{}{
							"type":        "boolean",
							"description": "Whether this item was completed.",
						},
						"notes": map[string]interface{}{
							"type":        "string",
							"description": "Optional notes for this item.",
						},
					},
				},
			},
			"declaration_text": map[string]interface{}{
				"type":        "string",
				"description": "Declaration text (only for type 'declaration').",
			},
			"accepted": map[string]interface{}{
				"type":        "boolean",
				"description": "Whether the declaration was accepted (only for type 'declaration').",
			},
			"attachments": map[string]interface{}{
				"type":        "array",
				"description": "Filenames of uploaded attachments (only for type 'document_upload'). Files must be uploaded alongside evidence.json.",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
		},
		"allOf": []interface{}{
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"type": map[string]interface{}{"const": "document_upload"},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"attachments"},
				},
			},
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"type": map[string]interface{}{"const": "checklist"},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"items"},
				},
			},
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"type": map[string]interface{}{"const": "declaration"},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"declaration_text", "accepted"},
				},
			},
		},
	}
}
