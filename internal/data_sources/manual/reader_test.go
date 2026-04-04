package manual

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	manualPkg "github.com/sigcomply/sigcomply-cli/internal/core/manual"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

func setupTest(t *testing.T) (context.Context, storage.Backend, *manualPkg.Catalog, *manualPkg.ExecutionState) {
	t.Helper()
	ctx := context.Background()
	backend := storage.NewLocalBackend(&storage.LocalConfig{Path: t.TempDir()})
	require.NoError(t, backend.Init(ctx))

	catalog, err := manualPkg.LoadCatalog("soc2")
	require.NoError(t, err)

	state := manualPkg.NewExecutionState("soc2")
	return ctx, backend, catalog, state
}

func storeJSON(t *testing.T, ctx context.Context, backend storage.Backend, path string, data interface{}) {
	t.Helper()
	jsonData, err := json.Marshal(data)
	require.NoError(t, err)
	_, err = backend.StoreRaw(ctx, path, jsonData, nil)
	require.NoError(t, err)
}

func TestReader_MissingEvidence(t *testing.T) {
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	reader := NewReader(backend, catalog, "soc2")
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)

	// All 4 entries should produce evidence (missing = not_uploaded)
	assert.Len(t, result.Evidence, 4)

	for _, ev := range result.Evidence {
		assert.Equal(t, "manual", ev.Collector)
		var data map[string]interface{}
		require.NoError(t, json.Unmarshal(ev.Data, &data))
		assert.Equal(t, "not_uploaded", data["status"])
	}
}

func TestReader_DocumentUpload(t *testing.T) {
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	// Store submitted evidence
	submitted := manualPkg.SubmittedEvidence{
		SchemaVersion: "1.0",
		EvidenceID:    "quarterly_access_review",
		Type:          manualPkg.EvidenceTypeDocumentUpload,
		Framework:     "soc2",
		Control:       "CC6.1",
		Period:        "2026-Q1",
		CompletedBy:   "admin@company.com",
		CompletedAt:   time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
		Attachments:   []string{"report.pdf"},
	}
	storeJSON(t, ctx, backend, "soc2/quarterly_access_review/2026-Q1/evidence.json", submitted)

	// Also store the attachment
	_, err := backend.StoreRaw(ctx, "soc2/quarterly_access_review/2026-Q1/report.pdf", []byte("PDF content"), nil)
	require.NoError(t, err)

	reader := NewReader(backend, catalog, "soc2")
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)

	// Find the quarterly_access_review evidence
	var found bool
	for _, ev := range result.Evidence {
		if ev.ResourceType == "manual:quarterly_access_review" {
			found = true
			var data map[string]interface{}
			require.NoError(t, json.Unmarshal(ev.Data, &data))
			assert.Equal(t, "uploaded", data["status"])
			assert.Equal(t, true, data["hash_verified"])
			assert.Equal(t, "admin@company.com", data["completed_by"])

			files, ok := data["files"].([]interface{})
			require.True(t, ok)
			assert.Len(t, files, 1)
		}
	}
	assert.True(t, found)
}

func TestReader_Checklist(t *testing.T) {
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	submitted := manualPkg.SubmittedEvidence{
		SchemaVersion: "1.0",
		EvidenceID:    "incident_response_test",
		Type:          manualPkg.EvidenceTypeChecklist,
		Framework:     "soc2",
		Control:       "CC7.2",
		Period:        "2026",
		CompletedBy:   "security@company.com",
		CompletedAt:   time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
		Items: []manualPkg.SubmittedChecklistItem{
			{ID: "plan_tested", Checked: true},
			{ID: "roles_verified", Checked: true},
			{ID: "communication_tested", Checked: true},
			{ID: "lessons_documented", Checked: false, Notes: "Pending follow-up"},
		},
	}
	storeJSON(t, ctx, backend, "soc2/incident_response_test/2026/evidence.json", submitted)

	reader := NewReader(backend, catalog, "soc2")
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)

	var found bool
	for _, ev := range result.Evidence {
		if ev.ResourceType == "manual:incident_response_test" {
			found = true
			var data map[string]interface{}
			require.NoError(t, json.Unmarshal(ev.Data, &data))
			assert.Equal(t, "uploaded", data["status"])
			items, ok := data["items"].([]interface{})
			require.True(t, ok)
			assert.Len(t, items, 4)
		}
	}
	assert.True(t, found)
}

func TestReader_Declaration(t *testing.T) {
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	accepted := true
	submitted := manualPkg.SubmittedEvidence{
		SchemaVersion:   "1.0",
		EvidenceID:      "risk_acceptance_signoff",
		Type:            manualPkg.EvidenceTypeDeclaration,
		Framework:       "soc2",
		Control:         "CC3.1",
		Period:          "2026-Q1",
		CompletedBy:     "ciso@company.com",
		CompletedAt:     time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
		DeclarationText: "I confirm the risk assessment is complete.",
		Accepted:        &accepted,
	}
	storeJSON(t, ctx, backend, "soc2/risk_acceptance_signoff/2026-Q1/evidence.json", submitted)

	reader := NewReader(backend, catalog, "soc2")
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)

	var found bool
	for _, ev := range result.Evidence {
		if ev.ResourceType == "manual:risk_acceptance_signoff" {
			found = true
			var data map[string]interface{}
			require.NoError(t, json.Unmarshal(ev.Data, &data))
			assert.Equal(t, "uploaded", data["status"])
			assert.Equal(t, true, data["accepted"])
		}
	}
	assert.True(t, found)
}

func TestReader_AlreadyAttested(t *testing.T) {
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	// Mark one entry as attested
	state.RecordAttestation("quarterly_access_review", "2026-Q1", "run-1", "attested", map[string]string{})

	reader := NewReader(backend, catalog, "soc2")
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)

	// Should have 3 evidence items (the attested one is skipped)
	assert.Len(t, result.Evidence, 3)

	for _, ev := range result.Evidence {
		assert.NotEqual(t, "manual:quarterly_access_review", ev.ResourceType)
	}
}

func TestReader_InvalidJSON(t *testing.T) {
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	// Store invalid JSON
	_, err := backend.StoreRaw(ctx, "soc2/quarterly_access_review/2026-Q1/evidence.json", []byte("{invalid"), nil)
	require.NoError(t, err)

	reader := NewReader(backend, catalog, "soc2")
	result, readErr := reader.Read(ctx, state, now)
	require.NoError(t, readErr)

	// Should have error for the invalid entry
	assert.GreaterOrEqual(t, len(result.Errors), 1)
	assert.Equal(t, "quarterly_access_review", result.Errors[0].EvidenceID)
}
