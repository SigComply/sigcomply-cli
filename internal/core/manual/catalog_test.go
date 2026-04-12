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
	assert.Equal(t, "CC6.3", entry.Control)
	assert.Equal(t, EvidenceTypeDocumentUpload, entry.Type)
	assert.Equal(t, FrequencyQuarterly, entry.Frequency)
	assert.Equal(t, "high", entry.Severity)
	assert.Equal(t, "security", entry.TSC)
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

	entries := catalog.EntriesForControl("CC6.3")
	assert.GreaterOrEqual(t, len(entries), 1)
	var found bool
	for _, e := range entries {
		if e.ID == "quarterly_access_review" {
			found = true
			break
		}
	}
	assert.True(t, found)
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

func TestCatalog_SOC2_Shape(t *testing.T) {
	catalog, err := LoadCatalog("soc2")
	require.NoError(t, err)

	// Expect 32 entries: 30 after physical access + 2 change management.
	assert.Equal(t, 32, len(catalog.Entries), "SOC 2 catalog should have 32 entries")

	// Every entry must have a non-empty TSC.
	for _, e := range catalog.Entries {
		assert.NotEmpty(t, e.TSC, "entry %s must have tsc set", e.ID)
		assert.Contains(t, []string{"security", "availability", "confidentiality", "privacy"}, e.TSC,
			"entry %s has unexpected tsc %q", e.ID, e.TSC)
	}

	// TSC distribution: 16 security + 3 availability + 1 confidentiality.
	tscCounts := map[string]int{}
	for _, e := range catalog.Entries {
		tscCounts[e.TSC]++
	}
	assert.Equal(t, 28, tscCounts["security"], "expected 28 security entries")
	assert.Equal(t, 3, tscCounts["availability"], "expected 3 availability entries")
	assert.Equal(t, 1, tscCounts["confidentiality"], "expected 1 confidentiality entry")

	// Exactly 2 entries should be marked optional: performance_review_security, cyber_liability_insurance.
	var optionalIDs []string
	for _, e := range catalog.Entries {
		if e.Optional {
			optionalIDs = append(optionalIDs, e.ID)
		}
	}
	assert.ElementsMatch(t,
		[]string{"performance_review_security", "cyber_liability_insurance"},
		optionalIDs,
		"unexpected set of optional entries")

	// All entries must have a category.
	for _, e := range catalog.Entries {
		assert.NotEmpty(t, e.Category, "entry %s must have category set", e.ID)
	}

	// Entry IDs must be unique.
	seen := map[string]bool{}
	for _, e := range catalog.Entries {
		assert.False(t, seen[e.ID], "duplicate entry id %s", e.ID)
		seen[e.ID] = true
	}
}
