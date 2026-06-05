package iso27001

// catalog_export_test.go — covers ManualCatalogExport and the manualPolicy.entry()
// builder, which are both at 0% before this file.

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
)

// TestManualCatalogExport_ContractShape verifies the SPA-facing Catalog shape.
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

// TestManualCatalogExport_CountMatchesManualCatalog ensures ManualCatalogExport
// and ManualCatalog are derived from the same source.
func TestManualCatalogExport_CountMatchesManualCatalog(t *testing.T) {
	export := ManualCatalogExport()
	catalog := ManualCatalog()
	if len(export.Entries) != len(catalog) {
		t.Errorf("ManualCatalogExport entries (%d) ≠ ManualCatalog keys (%d)",
			len(export.Entries), len(catalog))
	}
}

// TestManualCatalogExport_EvidenceTypeDefaults exercises the entry() fallback.
func TestManualCatalogExport_EvidenceTypeDefaults(t *testing.T) {
	cat := ManualCatalogExport()
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

// TestManualCatalogExport_SeverityNonEmpty verifies the severity default fires.
func TestManualCatalogExport_SeverityNonEmpty(t *testing.T) {
	cat := ManualCatalogExport()
	for _, e := range cat.Entries {
		if e.Severity == "" {
			t.Errorf("entry %q has empty Severity", e.ID)
		}
	}
}

// TestManualCatalogExport_ControlsNonEmpty verifies policy controls are present.
func TestManualCatalogExport_ControlsNonEmpty(t *testing.T) {
	cat := ManualCatalogExport()
	for _, e := range cat.Entries {
		if e.Control == "" {
			t.Errorf("entry %q has empty Control", e.ID)
		}
	}
}

// TestManualCatalog_GracePeriodForQuarterlyCadence verifies the grace-period
// logic: quarterly policies get 15 days, others get 30 days.
func TestManualCatalog_GracePeriodForQuarterlyCadence(t *testing.T) {
	cat := ManualCatalog()
	const quarterlyDays = 15
	const defaultDays = 30

	for id, e := range cat {
		days := int64(e.GracePeriod) / (24 * 3600 * 1_000_000_000)
		if e.Cadence == "quarterly" {
			if days != quarterlyDays {
				t.Errorf("entry %q: quarterly grace = %v (%d days); want %d days",
					id, e.GracePeriod, days, quarterlyDays)
			}
		} else {
			if days != defaultDays {
				t.Errorf("entry %q: non-quarterly grace = %v (%d days); want %d days",
					id, e.GracePeriod, days, defaultDays)
			}
		}
	}
}
