package vendorfanout_test

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vendorfanout"
)

const (
	cadenceAnnual = "annual"
	testEntryOdd  = "odd"
)

func baseCatalog() map[string]manual.CatalogEntry {
	return map[string]manual.CatalogEntry{
		"vendor_assurance": {EvidenceID: "vendor_assurance", Cadence: cadenceAnnual, FanOut: manual.FanOutVendors},
		"cuec_mapping":     {EvidenceID: "cuec_mapping", Cadence: cadenceAnnual, FanOut: manual.FanOutSubserviceVendors},
		"security_policy":  {EvidenceID: "security_policy", Cadence: cadenceAnnual},
	}
}

func register(t *testing.T, body string) *spec.VendorRegister {
	t.Helper()
	cfg, err := spec.LoadProjectConfig([]byte("schema_version: project.v1\nframework: soc2\n" + body))
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	reg, err := spec.LoadVendorRegister(&cfg)
	if err != nil {
		t.Fatalf("LoadVendorRegister: %v", err)
	}
	return reg
}

const fullRegister = `experimental:
  vendors:
    register:
      - {id: acme_cloud, name: Acme Cloud, tier: critical, subservice: true, assurance_period_end: "2026-03-31"}
      - {id: initech, name: Initech, tier: moderate}
      - {id: zeta, name: Zeta, tier: low, tier_rationale: No data., approved_by: ciso@example.com}
`

func TestApply_ExpandsVendorFanOut(t *testing.T) {
	got := vendorfanout.Apply(baseCatalog(), register(t, fullRegister))

	va := got["vendor_assurance"]
	if len(va.Instances) != 3 {
		t.Fatalf("vendor_assurance instances = %d; want 3", len(va.Instances))
	}
	// Sorted by ID on load, so the order is deterministic.
	if va.Instances[0].ID != "acme_cloud" || va.Instances[2].ID != "zeta" {
		t.Fatalf("instances not in register order: %+v", va.Instances)
	}
	// Every tier but low owes an artifact.
	if !va.Instances[0].Required || !va.Instances[1].Required {
		t.Fatalf("critical/moderate should be required: %+v", va.Instances)
	}
	if va.Instances[2].Required {
		t.Fatalf("low tier should not be required: %+v", va.Instances[2])
	}
	// The exemption carries its justification through.
	if va.Instances[2].ExemptionReason == "" || va.Instances[2].ApprovedBy == "" {
		t.Fatalf("low-tier exemption lost its justification: %+v", va.Instances[2])
	}
	if va.Instances[0].AssurancePeriodEnd != "2026-03-31" {
		t.Fatalf("assurance date lost: %+v", va.Instances[0])
	}
}

// CUEC mapping fans out over subservice organizations only — CUECs come
// from a subservice organization's own report, so a vendor that is not
// one has none to map.
func TestApply_SubserviceFanOutSelectsOnlySubserviceVendors(t *testing.T) {
	got := vendorfanout.Apply(baseCatalog(), register(t, fullRegister))

	cuec := got["cuec_mapping"]
	if len(cuec.Instances) != 1 || cuec.Instances[0].ID != "acme_cloud" {
		t.Fatalf("cuec_mapping instances = %+v; want just acme_cloud", cuec.Instances)
	}
	// Subservice membership, not tier, decides here — so the instance
	// is required regardless of what tier it sits at.
	if !cuec.Instances[0].Required {
		t.Fatalf("subservice instance should be required: %+v", cuec.Instances[0])
	}
}

func TestApply_NonFanOutEntryUntouched(t *testing.T) {
	got := vendorfanout.Apply(baseCatalog(), register(t, fullRegister))
	if len(got["security_policy"].Instances) != 0 {
		t.Fatalf("a non-fan-out entry gained instances: %+v", got["security_policy"])
	}
}

// The three no-op cases. Each must leave the single-folder behavior
// exactly as it was — that property is what makes this feature additive
// for every project that predates it.
func TestApply_NoOpCases(t *testing.T) {
	t.Run("nil register", func(t *testing.T) {
		got := vendorfanout.Apply(baseCatalog(), nil)
		for id, e := range got {
			if len(e.Instances) != 0 {
				t.Fatalf("%s gained instances with no register: %+v", id, e)
			}
		}
	})

	t.Run("register with no subservice vendors", func(t *testing.T) {
		reg := register(t, `experimental:
  vendors:
    register:
      - {id: initech, name: Initech, tier: high}
`)
		got := vendorfanout.Apply(baseCatalog(), reg)
		if len(got["cuec_mapping"].Instances) != 0 {
			t.Fatalf("cuec_mapping fanned out with no subservice vendors: %+v", got["cuec_mapping"])
		}
		// ...while the plain vendor fan-out still expands.
		if len(got["vendor_assurance"].Instances) != 1 {
			t.Fatalf("vendor_assurance = %+v; want 1 instance", got["vendor_assurance"])
		}
	})

	t.Run("empty catalog", func(t *testing.T) {
		if got := vendorfanout.Apply(nil, register(t, fullRegister)); len(got) != 0 {
			t.Fatalf("Apply(nil) = %+v", got)
		}
	})
}

// An unknown fan-out kind must fall back to the single folder rather
// than silently scanning nothing, which would turn a missing document
// into a pass.
func TestApply_UnknownFanOutKindFallsBackToSingleFolder(t *testing.T) {
	cat := map[string]manual.CatalogEntry{
		testEntryOdd: {EvidenceID: testEntryOdd, FanOut: "not_a_real_set"},
	}
	got := vendorfanout.Apply(cat, register(t, fullRegister))
	if len(got[testEntryOdd].Instances) != 0 {
		t.Fatalf("unknown fan-out kind expanded: %+v", got[testEntryOdd])
	}
	if got[testEntryOdd].EvidenceID != testEntryOdd {
		t.Fatalf("entry mangled: %+v", got[testEntryOdd])
	}
}

// Apply must not mutate the framework's catalog map, which is shared
// process-wide and rebuilt per call only by convention.
func TestApply_DoesNotMutateInput(t *testing.T) {
	in := baseCatalog()
	_ = vendorfanout.Apply(in, register(t, fullRegister))
	if len(in["vendor_assurance"].Instances) != 0 {
		t.Fatalf("Apply mutated its input: %+v", in["vendor_assurance"])
	}
}
