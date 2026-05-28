package soc2

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
	if len(fw.Controls()) < 30 {
		t.Errorf("want at least 30 controls; got %d", len(fw.Controls()))
	}
	if len(fw.Policies()) < 100 {
		t.Errorf("want at least 100 policies; got %d", len(fw.Policies()))
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
	for _, ref := range New().Policies() {
		if _, ok := set.Policies.Lookup(ref.PolicyID); !ok {
			t.Errorf("policy %q not registered", ref.PolicyID)
		}
	}
	// Every slot.Accepts type must be a registered evidence type, and
	// every RuleRef must resolve.
	if err := evidencetypes.VerifyRegistrations(set); err != nil {
		t.Fatalf("VerifyRegistrations: %v", err)
	}
}

func TestPolicies_EveryAutomatedReferencesKnownTypesAndRules(t *testing.T) {
	set := registry.NewSet()
	if err := evidencetypes.Register(set); err != nil {
		t.Fatalf("register evidence types: %v", err)
	}
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for _, p := range Policies() {
		if p.EvidenceMode == "" {
			t.Errorf("policy %q missing evidence_mode", p.ID)
		}
		if p.RuleRef != "" {
			if _, ok := set.Rules.Lookup(p.RuleRef); !ok {
				t.Errorf("policy %q references unregistered rule %q", p.ID, p.RuleRef)
			}
		}
		if !strings.HasPrefix(p.ID, "soc2.") {
			t.Errorf("policy %q must be soc2-namespaced", p.ID)
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
	if _, ok := cat["access_review_quarterly"]; !ok {
		t.Error("access_review_quarterly missing from catalog")
	}
}

func TestPolicyIDs_AreUnique(t *testing.T) {
	seen := map[string]struct{}{}
	for _, p := range Policies() {
		if _, dup := seen[p.ID]; dup {
			t.Errorf("duplicate policy ID %q", p.ID)
		}
		seen[p.ID] = struct{}{}
	}
}
