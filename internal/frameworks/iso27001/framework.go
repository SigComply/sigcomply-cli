package iso27001

import (
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// init registers this framework's factory so commands can resolve it
// by ID without a hardcoded switch. See internal/frameworks/registry.go.
func init() {
	frameworks.RegisterFactory(FrameworkID, frameworks.Factory{
		Register:      Register,
		ManualCatalog: ManualCatalog,
	})
}

// FrameworkID is the registered identifier.
const FrameworkID = "iso27001"

// FrameworkVersion stamps every PolicyRef returned by this framework.
const FrameworkVersion = "iso27001-2022@1.0.0"

// Framework is the in-process ISO/IEC 27001:2022 framework.
type Framework struct{}

// New returns a fresh Framework value.
func New() *Framework { return &Framework{} }

// ID implements core.Framework.
func (*Framework) ID() string { return FrameworkID }

// Version implements core.Framework.
func (*Framework) Version() string { return FrameworkVersion }

// Controls implements core.Framework.
func (*Framework) Controls() []core.Control { return Controls() }

// Policies implements core.Framework.
func (*Framework) Policies() []core.PolicyRef {
	policies := Policies()
	refs := make([]core.PolicyRef, len(policies))
	for i := range policies {
		refs[i] = core.PolicyRef{PolicyID: policies[i].ID}
	}
	return refs
}

// Policies returns the full ISO 27001 policy library.
func Policies() []core.Policy {
	out := make([]core.Policy, 0, 110)
	out = append(out, technologicalPolicies()...)
	out = append(out, organizationalAutomatedPolicies()...)
	out = append(out, manualPolicies()...)
	return out
}

// Rules returns the Go rule implementations. ISO 27001 expresses every
// automated check in the pass_when DSL, so there are none.
func Rules() []core.Rule { return nil }

// Register populates the framework and policy registries. Errors surface
// as exit-3 configuration errors at startup.
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

// ManualCatalog returns one catalog entry per manual policy.
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
