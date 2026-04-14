package manual

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubmittedEvidence_JSONRoundTrip(t *testing.T) {
	accepted := true
	original := SubmittedEvidence{
		SchemaVersion: "1.0",
		EvidenceID:    "quarterly_access_review",
		Type:          EvidenceTypeDocumentUpload,
		Framework:     "soc2",
		Control:       "CC6.1",
		Period:        "2026-Q1",
		CompletedBy:   "admin@company.com",
		CompletedAt:   time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC),
		Attachments:   []string{"report.pdf"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded SubmittedEvidence
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.SchemaVersion, decoded.SchemaVersion)
	assert.Equal(t, original.EvidenceID, decoded.EvidenceID)
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Period, decoded.Period)
	assert.Equal(t, original.Attachments, decoded.Attachments)

	// Test checklist round-trip
	checklist := SubmittedEvidence{
		SchemaVersion: "1.0",
		EvidenceID:    "incident_response_test",
		Type:          EvidenceTypeChecklist,
		Framework:     "soc2",
		Control:       "CC7.2",
		Period:        "2026",
		CompletedBy:   "admin@company.com",
		CompletedAt:   time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC),
		Items: []SubmittedChecklistItem{
			{ID: "plan_tested", Checked: true},
			{ID: "roles_verified", Checked: true, Notes: "All roles confirmed"},
		},
	}

	data, err = json.Marshal(checklist)
	require.NoError(t, err)

	var decodedChecklist SubmittedEvidence
	require.NoError(t, json.Unmarshal(data, &decodedChecklist))
	assert.Len(t, decodedChecklist.Items, 2)
	assert.True(t, decodedChecklist.Items[0].Checked)

	// Test declaration round-trip
	declaration := SubmittedEvidence{
		SchemaVersion:   "1.0",
		EvidenceID:      "risk_acceptance_signoff",
		Type:            EvidenceTypeDeclaration,
		Framework:       "soc2",
		Control:         "CC3.1",
		Period:          "2026-Q1",
		CompletedBy:     "ciso@company.com",
		CompletedAt:     time.Date(2026, 3, 31, 10, 0, 0, 0, time.UTC),
		DeclarationText: "I confirm the risk assessment is complete.",
		Accepted:        &accepted,
	}

	data, err = json.Marshal(declaration)
	require.NoError(t, err)

	var decodedDecl SubmittedEvidence
	require.NoError(t, json.Unmarshal(data, &decodedDecl))
	assert.NotNil(t, decodedDecl.Accepted)
	assert.True(t, *decodedDecl.Accepted)
}
