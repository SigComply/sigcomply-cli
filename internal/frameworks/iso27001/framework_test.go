package iso27001

import (
	"strings"
	"testing"

	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

func TestFramework_BasicMetadata(t *testing.T) {
	fw := New()
	if fw.ID() != FrameworkID {
		t.Errorf("ID = %q; want %q", fw.ID(), FrameworkID)
	}
	if fw.Version() != FrameworkVersion {
		t.Errorf("Version = %q; want %q", fw.Version(), FrameworkVersion)
	}
	if len(fw.Controls()) != 93 {
		t.Errorf("want 93 Annex A controls; got %d", len(fw.Controls()))
	}
	if len(fw.Policies()) < 90 {
		t.Errorf("want at least 90 policies; got %d", len(fw.Policies()))
	}
}

func TestRegister_PopulatesRegistriesAndVerifies(t *testing.T) {
	set := registry.NewSet()
	if err := evidencetypes.Register(set); err != nil {
		t.Fatalf("register evidence types: %v", err)
	}
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := evidencetypes.VerifyRegistrations(set); err != nil {
		t.Fatalf("VerifyRegistrations: %v", err)
	}
}

func TestPolicies_NamespacedAndUnique(t *testing.T) {
	seen := map[string]struct{}{}
	for _, p := range Policies() {
		if !strings.HasPrefix(p.ID, "iso27001.") {
			t.Errorf("policy %q must be iso27001-namespaced", p.ID)
		}
		if p.EvidenceMode == "" {
			t.Errorf("policy %q missing evidence_mode", p.ID)
		}
		if _, dup := seen[p.ID]; dup {
			t.Errorf("duplicate policy ID %q", p.ID)
		}
		seen[p.ID] = struct{}{}
	}
}

func TestControls_EveryPolicyControlIsRegistered(t *testing.T) {
	controlIDs := map[string]struct{}{}
	for _, c := range Controls() {
		controlIDs[c.ID] = struct{}{}
	}
	for _, p := range Policies() {
		if _, ok := controlIDs[p.Control]; !ok {
			t.Errorf("policy %q references control %q not in the catalog", p.ID, p.Control)
		}
	}
}

func TestManualCatalog_CoversEveryManualPolicy(t *testing.T) {
	cat := ManualCatalog()
	for _, p := range Policies() {
		if p.CatalogEntry == "" {
			continue
		}
		if _, ok := cat[p.CatalogEntry]; !ok {
			t.Errorf("manual policy %q references catalog entry %q not in ManualCatalog", p.ID, p.CatalogEntry)
		}
	}
}
