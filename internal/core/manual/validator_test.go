package manual

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return data
}

func TestValidateSubmittedEvidence_Valid(t *testing.T) {
	accepted := true
	cases := map[string]SubmittedEvidence{
		"document_upload": {
			SchemaVersion: "1.0",
			EvidenceID:    "quarterly_access_review",
			Type:          EvidenceTypeDocumentUpload,
			Framework:     "soc2",
			Control:       "CC6.1",
			Period:        "2026-Q1",
			CompletedBy:   "admin@example.com",
			CompletedAt:   time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
			Attachments:   []string{"report.pdf"},
		},
		"checklist": {
			SchemaVersion: "1.0",
			EvidenceID:    "incident_response_test",
			Type:          EvidenceTypeChecklist,
			Framework:     "soc2",
			Control:       "CC7.2",
			Period:        "2026",
			CompletedBy:   "sec@example.com",
			CompletedAt:   time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
			Items: []SubmittedChecklistItem{
				{ID: "plan_tested", Checked: true},
			},
		},
		"declaration": {
			SchemaVersion:   "1.0",
			EvidenceID:      "risk_acceptance_signoff",
			Type:            EvidenceTypeDeclaration,
			Framework:       "soc2",
			Control:         "CC3.1",
			Period:          "2026-Q1",
			CompletedBy:     "ciso@example.com",
			CompletedAt:     time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
			DeclarationText: "I confirm.",
			Accepted:        &accepted,
		},
	}

	for name, sub := range cases {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, ValidateSubmittedEvidence(mustJSON(t, sub)))
		})
	}
}

func TestValidateSubmittedEvidence_MissingRequiredTopLevel(t *testing.T) {
	// Missing "evidence_id", "period", etc.
	raw := []byte(`{"schema_version":"1.0","type":"declaration","framework":"soc2"}`)
	err := ValidateSubmittedEvidence(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema violation")
}

func TestValidateSubmittedEvidence_ChecklistMissingItems(t *testing.T) {
	// Valid top-level fields but type=checklist without items[]
	sub := map[string]interface{}{
		"schema_version": "1.0",
		"evidence_id":    "incident_response_test",
		"type":           "checklist",
		"framework":      "soc2",
		"control":        "CC7.2",
		"period":         "2026",
		"completed_by":   "sec@example.com",
		"completed_at":   "2026-03-10T00:00:00Z",
	}
	err := ValidateSubmittedEvidence(mustJSON(t, sub))
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "items")
}

func TestValidateSubmittedEvidence_DocumentUploadMissingAttachments(t *testing.T) {
	sub := map[string]interface{}{
		"schema_version": "1.0",
		"evidence_id":    "quarterly_access_review",
		"type":           "document_upload",
		"framework":      "soc2",
		"control":        "CC6.1",
		"period":         "2026-Q1",
		"completed_by":   "admin@example.com",
		"completed_at":   "2026-03-10T00:00:00Z",
	}
	err := ValidateSubmittedEvidence(mustJSON(t, sub))
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "attachments")
}

func TestValidateSubmittedEvidence_DeclarationMissingAccepted(t *testing.T) {
	sub := map[string]interface{}{
		"schema_version":   "1.0",
		"evidence_id":      "risk_acceptance_signoff",
		"type":             "declaration",
		"framework":        "soc2",
		"control":          "CC3.1",
		"period":           "2026-Q1",
		"completed_by":     "ciso@example.com",
		"completed_at":     "2026-03-10T00:00:00Z",
		"declaration_text": "I confirm.",
	}
	err := ValidateSubmittedEvidence(mustJSON(t, sub))
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "accepted")
}

func TestValidateSubmittedEvidence_InvalidJSON(t *testing.T) {
	err := ValidateSubmittedEvidence([]byte(`{not json`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse JSON")
}

func TestValidateSubmittedEvidence_UnknownEvidenceType(t *testing.T) {
	sub := map[string]interface{}{
		"schema_version": "1.0",
		"evidence_id":    "something",
		"type":           "video_upload", // not in enum
		"framework":      "soc2",
		"control":        "CC6.1",
		"period":         "2026-Q1",
		"completed_by":   "admin@example.com",
		"completed_at":   "2026-03-10T00:00:00Z",
	}
	err := ValidateSubmittedEvidence(mustJSON(t, sub))
	require.Error(t, err)
}
