package manual

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadCatalog_SOC2(t *testing.T) {
	catalog, err := LoadCatalog("soc2")
	require.NoError(t, err)

	assert.Equal(t, "soc2", catalog.Framework)
	assert.Equal(t, "1.0", catalog.Version)
	assert.GreaterOrEqual(t, len(catalog.Entries), 4)
}

func TestLoadCatalog_NotFound(t *testing.T) {
	_, err := LoadCatalog("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no manual evidence catalog")
}

func TestCatalog_GetEntry(t *testing.T) {
	catalog, err := LoadCatalog("soc2")
	require.NoError(t, err)

	entry := catalog.GetEntry("quarterly_access_review")
	require.NotNil(t, entry)
	assert.Equal(t, "CC6.1", entry.Control)
	assert.Equal(t, EvidenceTypeDocumentUpload, entry.Type)
	assert.Equal(t, FrequencyQuarterly, entry.Frequency)
	assert.Equal(t, "high", entry.Severity)
}

func TestCatalog_GetEntry_NotFound(t *testing.T) {
	catalog, err := LoadCatalog("soc2")
	require.NoError(t, err)

	entry := catalog.GetEntry("nonexistent")
	assert.Nil(t, entry)
}

func TestCatalog_EntriesForControl(t *testing.T) {
	catalog, err := LoadCatalog("soc2")
	require.NoError(t, err)

	entries := catalog.EntriesForControl("CC6.1")
	assert.Len(t, entries, 1)
	assert.Equal(t, "quarterly_access_review", entries[0].ID)
}

func TestCatalog_EntriesForControl_None(t *testing.T) {
	catalog, err := LoadCatalog("soc2")
	require.NoError(t, err)

	entries := catalog.EntriesForControl("CC99.9")
	assert.Empty(t, entries)
}

func TestCatalog_ChecklistEntry(t *testing.T) {
	catalog, err := LoadCatalog("soc2")
	require.NoError(t, err)

	entry := catalog.GetEntry("incident_response_test")
	require.NotNil(t, entry)
	assert.Equal(t, EvidenceTypeChecklist, entry.Type)
	assert.GreaterOrEqual(t, len(entry.Items), 3)
	assert.True(t, entry.Items[0].Required)
}

func TestCatalog_DeclarationEntry(t *testing.T) {
	catalog, err := LoadCatalog("soc2")
	require.NoError(t, err)

	entry := catalog.GetEntry("risk_acceptance_signoff")
	require.NotNil(t, entry)
	assert.Equal(t, EvidenceTypeDeclaration, entry.Type)
	assert.NotEmpty(t, entry.DeclarationText)
}
