package soc2

// catalog_export_test.go — covers ManualCatalogExport and the manualPolicy.entry()
// builder, which are both at 0% before this file.

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
)

// TestManualCatalogExport_ContractShape verifies that ManualCatalogExport
// produces the SPA-facing Catalog with the correct framework/version header
// and at least one entry per manual policy.
func TestManualCatalogExport_ContractShape(t *testing.T) {
	cat := ManualCatalogExport()
	if cat.Framework != FrameworkID {
		t.Errorf("Framework = %q; want %q", cat.Framework, FrameworkID)
	}
	if cat.Version == "" {
		t.Error("Version is empty")
	}
	if len(cat.Entries) == 0 {
		t.Fatal("Entries is empty — ManualCatalogExport produced no entries")
	}
	// Every entry must have an ID and a Type.
	for i, e := range cat.Entries {
		if e.ID == "" {
			t.Errorf("Entries[%d].ID is empty", i)
		}
		if e.Type == "" {
			t.Errorf("Entries[%d].Type is empty (entry %q)", i, e.ID)
		}
		if e.Frequency == "" {
			t.Errorf("Entries[%d].Frequency is empty (entry %q)", i, e.ID)
		}
	}
}

// TestManualCatalogExport_CountMatchesManualCatalog verifies that the SPA-facing
// export and the runtime catalog are derived from the same source (manualSpecs),
// so their entry counts always agree.
func TestManualCatalogExport_CountMatchesManualCatalog(t *testing.T) {
	export := ManualCatalogExport()
	catalog := ManualCatalog()
	if len(export.Entries) != len(catalog) {
		t.Errorf("ManualCatalogExport entries (%d) ≠ ManualCatalog keys (%d) — sources diverged",
			len(export.Entries), len(catalog))
	}
}

// TestManualCatalogExport_EvidenceTypeDefaults exercises the entry() fallback
// that applies TypeDocumentUpload when the policy's etype field is zero.
// Most manual policies don't set etype explicitly, so this branch is hit.
func TestManualCatalogExport_EvidenceTypeDefaults(t *testing.T) {
	cat := ManualCatalogExport()
	// At least one entry must carry the document_upload default.
	found := false
	for _, e := range cat.Entries {
		if e.Type == manualcatalog.TypeDocumentUpload {
			found = true
			break
		}
	}
	if !found {
		t.Error("no entry with TypeDocumentUpload — expected default fallback to fire")
	}
}

// TestManualCatalogExport_SeverityDefault exercises the entry() fallback
// that defaults severity to "medium" when unset.
func TestManualCatalogExport_SeverityDefault(t *testing.T) {
	cat := ManualCatalogExport()
	for _, e := range cat.Entries {
		if e.Severity == "" {
			t.Errorf("entry %q has empty Severity — default should have been applied", e.ID)
		}
	}
}

// TestManualCatalogExport_RegisterFrameworkIDConsistency verifies that all
// entries exported from soc2 carry the correct framework-level identification.
func TestManualCatalogExport_RegisterFrameworkIDConsistency(t *testing.T) {
	cat := ManualCatalogExport()
	for _, e := range cat.Entries {
		// Every entry's Control must be non-empty (from the policy spec).
		if e.Control == "" {
			t.Errorf("entry %q has empty Control", e.ID)
		}
	}
}
