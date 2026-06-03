package soc2

import (
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// init registers this framework's factory so commands can resolve it
// by ID without a hardcoded switch. See internal/frameworks/registry.go.
func init() {
	frameworks.RegisterFactory(FrameworkID, frameworks.Factory{
		Register:            Register,
		ManualCatalog:       ManualCatalog,
		ManualCatalogExport: ManualCatalogExport,
	})
}

// FrameworkID is the registered identifier.
const FrameworkID = "soc2"

// FrameworkVersion stamps every PolicyRef returned by this framework.
const FrameworkVersion = "soc2-2017@1.0.0"

// Framework is the in-process SOC 2 framework.
type Framework struct{}

// New returns a fresh Framework value.
func New() *Framework { return &Framework{} }

// ID implements core.Framework.
func (*Framework) ID() string { return FrameworkID }

// Version implements core.Framework.
func (*Framework) Version() string { return FrameworkVersion }

// Controls implements core.Framework.
func (*Framework) Controls() []core.Control { return Controls() }

// Policies implements core.Framework: the policy-ID references the
// planner walks.
func (*Framework) Policies() []core.PolicyRef {
	policies := Policies()
	refs := make([]core.PolicyRef, len(policies))
	for i := range policies {
		refs[i] = core.PolicyRef{PolicyID: policies[i].ID}
	}
	return refs
}

// Policies returns the full SOC 2 policy library: automated checks
// (pass_when + rule: escape hatches) and manual-evidence policies.
func Policies() []core.Policy {
	out := make([]core.Policy, 0, 160)
	out = append(out, cc6Policies()...)
	out = append(out, cc6SecretHygienePolicies()...)
	out = append(out, cc7Policies()...)
	out = append(out, cc8Policies()...)
	out = append(out, availabilityPolicies()...)
	out = append(out, confidentialityPolicies()...)
	out = append(out, manualPolicies()...)
	return out
}

// Rules returns the Go rule implementations referenced by RuleRef
// policies. Empty today — soc2 authors every policy with the pass_when
// DSL (see rules.go).
func Rules() []core.Rule {
	return rules()
}

// Register populates the framework, rule, and policy registries.
// Errors surface as exit-3 configuration errors at startup.
func Register(set *registry.Set) error {
	if err := set.Frameworks.Register(New()); err != nil {
		return err
	}
	for _, r := range Rules() {
		if err := set.Rules.Register(r); err != nil {
			return err
		}
	}
	policies := Policies()
	for i := range policies {
		if err := set.Policies.Register(policies[i]); err != nil {
			return err
		}
	}
	return nil
}

// ManualCatalogExport returns the descriptive, presentation-facing
// catalog for `sigcomply evidence catalog` (consumed by the Evidence
// SPA). Derived from the same manualSpecs() as the policy library, so
// the two cannot drift.
func ManualCatalogExport() manualcatalog.Catalog {
	specs := manualSpecs()
	entries := make([]manualcatalog.Entry, len(specs))
	for i := range specs {
		entries[i] = specs[i].entry()
	}
	return manualcatalog.Catalog{
		Framework: FrameworkID,
		Version:   "1.0",
		Entries:   entries,
	}
}

// ManualCatalog returns one catalog entry per manual policy. The catalog
// ID equals each manual policy's CatalogEntry; cadence and grace period
// follow the policy's declared cadence.
func ManualCatalog() map[string]manual.CatalogEntry {
	out := make(map[string]manual.CatalogEntry)
	mp := manualPolicies()
	for i := range mp {
		p := &mp[i]
		if p.CatalogEntry == "" {
			continue
		}
		grace := 30 * 24 * time.Hour
		if p.Cadence == "quarterly" {
			grace = 15 * 24 * time.Hour
		}
		out[p.CatalogEntry] = manual.CatalogEntry{
			EvidenceID:   p.CatalogEntry,
			Filename:     "evidence.pdf",
			Cadence:      p.Cadence,
			TemporalRule: "retrospective",
			GracePeriod:  grace,
		}
	}
	return out
}
