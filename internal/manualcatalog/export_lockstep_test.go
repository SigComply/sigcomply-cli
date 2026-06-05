package manualcatalog_test

import (
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
)

// frameworkUnderTest pairs a framework's exported catalog with its
// authoritative manual policies so one table drives both frameworks.
type frameworkUnderTest struct {
	id       string
	export   func() manualcatalog.Catalog
	policies func() []core.Policy
}

func frameworks() []frameworkUnderTest {
	return []frameworkUnderTest{
		{"soc2", soc2.ManualCatalogExport, soc2.Policies},
		{"iso27001", iso27001.ManualCatalogExport, iso27001.Policies},
	}
}

// manualPolicies filters a framework's full policy library down to the
// manual-evidence policies — the policies the export must mirror.
func manualPolicies(all []core.Policy) []core.Policy {
	var out []core.Policy
	for i := range all {
		if all[i].EvidenceMode == core.EvidenceModeManual {
			out = append(out, all[i])
		}
	}
	return out
}

// TestExport_TopLevelShape asserts framework id and a non-empty version
// and entries for each framework.
func TestExport_TopLevelShape(t *testing.T) {
	for _, fw := range frameworks() {
		t.Run(fw.id, func(t *testing.T) {
			cat := fw.export()
			if cat.Framework != fw.id {
				t.Errorf("Framework = %q; want %q", cat.Framework, fw.id)
			}
			if cat.Version == "" {
				t.Error("Version is empty")
			}
			if len(cat.Entries) == 0 {
				t.Fatal("no entries exported")
			}
		})
	}
}

// TestExport_InLockstepWithManualPolicies is the anti-drift guarantee:
// the descriptive catalog export and the policy library both derive from
// the same per-framework manualSpecs(), so the set of exported catalog
// IDs must exactly equal the set of manual policies' CatalogEntry values,
// with matching controls. If someone adds a manual policy but forgets the
// catalog (or vice versa), this fails.
func TestExport_InLockstepWithManualPolicies(t *testing.T) {
	for _, fw := range frameworks() {
		t.Run(fw.id, func(t *testing.T) {
			cat := fw.export()
			manual := manualPolicies(fw.policies())

			if len(cat.Entries) != len(manual) {
				t.Fatalf("export has %d entries but framework has %d manual policies — they have drifted",
					len(cat.Entries), len(manual))
			}

			byID := make(map[string]manualcatalog.Entry, len(cat.Entries))
			for _, e := range cat.Entries {
				if _, dup := byID[e.ID]; dup {
					t.Errorf("duplicate export entry id %q", e.ID)
				}
				byID[e.ID] = e
			}

			for _, p := range manual {
				if p.CatalogEntry == "" {
					t.Errorf("manual policy %q has empty CatalogEntry", p.ID)
					continue
				}
				e, ok := byID[p.CatalogEntry]
				if !ok {
					t.Errorf("manual policy %q (catalog %q) has no matching export entry",
						p.ID, p.CatalogEntry)
					continue
				}
				if want := core.PrimaryControlID(p.Controls); e.Control != want {
					t.Errorf("entry %q control = %q; policy %q control = %q",
						e.ID, e.Control, p.ID, want)
				}
			}
		})
	}
}

// TestExport_RequiredFieldsNonEmpty asserts every exported entry carries
// the fields the SPA always renders. Empty values would surface as blank
// cards in the SPA dashboard.
func TestExport_RequiredFieldsNonEmpty(t *testing.T) {
	validType := map[manualcatalog.EvidenceType]bool{
		manualcatalog.TypeDocumentUpload: true,
		manualcatalog.TypeChecklist:      true,
		manualcatalog.TypeDeclaration:    true,
	}
	validFreq := map[manualcatalog.Frequency]bool{
		manualcatalog.FrequencyDaily: true, manualcatalog.FrequencyWeekly: true,
		manualcatalog.FrequencyMonthly: true, manualcatalog.FrequencyQuarterly: true,
		manualcatalog.FrequencyYearly: true,
	}
	validTemporal := map[manualcatalog.TemporalRule]bool{
		manualcatalog.TemporalRetrospective: true,
		manualcatalog.TemporalAnytime:       true,
	}
	for _, fw := range frameworks() {
		t.Run(fw.id, func(t *testing.T) {
			for _, e := range fw.export().Entries {
				if e.ID == "" {
					t.Error("entry with empty ID")
				}
				if e.Control == "" {
					t.Errorf("entry %q has empty Control", e.ID)
				}
				if e.Name == "" {
					t.Errorf("entry %q has empty Name", e.ID)
				}
				if e.Description == "" {
					t.Errorf("entry %q has empty Description", e.ID)
				}
				if e.Severity == "" {
					t.Errorf("entry %q has empty Severity", e.ID)
				}
				if e.GracePeriod == "" {
					t.Errorf("entry %q has empty GracePeriod", e.ID)
				}
				if !validType[e.Type] {
					t.Errorf("entry %q has invalid Type %q (not a SPA EvidenceType)", e.ID, e.Type)
				}
				if !validFreq[e.Frequency] {
					t.Errorf("entry %q has invalid Frequency %q (not a SPA Frequency)", e.ID, e.Frequency)
				}
				if !validTemporal[e.TemporalRule] {
					t.Errorf("entry %q has invalid TemporalRule %q", e.ID, e.TemporalRule)
				}
			}
		})
	}
}

// TestExport_ChecklistAndDeclarationContentPresent asserts the type-
// specific SPA payloads: a checklist entry must carry items (each with a
// non-empty id+text), and a declaration entry must carry declaration
// text. document_upload entries carry neither (they are produced
// externally and the SPA filters them out).
func TestExport_ChecklistAndDeclarationContentPresent(t *testing.T) {
	for _, fw := range frameworks() {
		t.Run(fw.id, func(t *testing.T) {
			var sawChecklist, sawDeclaration bool
			for _, e := range fw.export().Entries {
				switch e.Type {
				case manualcatalog.TypeChecklist:
					sawChecklist = true
					if len(e.Items) == 0 {
						t.Errorf("checklist entry %q has no items", e.ID)
					}
					for _, it := range e.Items {
						if it.ID == "" || it.Text == "" {
							t.Errorf("checklist entry %q has an item with empty id/text: %+v", e.ID, it)
						}
					}
				case manualcatalog.TypeDeclaration:
					sawDeclaration = true
					if e.DeclarationText == "" {
						t.Errorf("declaration entry %q has empty DeclarationText", e.ID)
					}
				case manualcatalog.TypeDocumentUpload:
					if len(e.Items) != 0 || e.DeclarationText != "" {
						t.Errorf("document_upload entry %q unexpectedly carries form content", e.ID)
					}
				}
			}
			if !sawChecklist {
				t.Error("expected at least one checklist entry")
			}
			if !sawDeclaration {
				t.Error("expected at least one declaration entry")
			}
		})
	}
}

// TestExport_JSONKeysMatchSPAContract marshals the real export and asserts
// the exact JSON key set the SPA (scripts/fetch-catalogs.ts) parses,
// across a representative entry of every type, so a renamed json tag is
// caught against live data rather than only the type definition.
func TestExport_JSONKeysMatchSPAContract(t *testing.T) {
	for _, fw := range frameworks() {
		t.Run(fw.id, func(t *testing.T) {
			b, err := json.Marshal(fw.export())
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var top map[string]json.RawMessage
			if err := json.Unmarshal(b, &top); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for _, k := range []string{"framework", "version", "entries"} {
				if _, ok := top[k]; !ok {
					t.Errorf("top-level export missing key %q", k)
				}
			}
			var entries []map[string]json.RawMessage
			if err := json.Unmarshal(top["entries"], &entries); err != nil {
				t.Fatalf("unmarshal entries: %v", err)
			}
			alwaysPresent := []string{
				"id", "control", "type", "frequency", "temporal_rule",
				"grace_period", "name", "description", "severity",
			}
			for _, e := range entries {
				for _, k := range alwaysPresent {
					if _, ok := e[k]; !ok {
						t.Errorf("entry missing always-present key %q: %v", k, e)
					}
				}
			}
		})
	}
}
