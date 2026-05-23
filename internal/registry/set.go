package registry

import "github.com/sigcomply/sigcomply-cli/internal/core"

// Set is the bundle of all five registries the orchestrator passes
// through the stack. Constructed empty by NewSet, populated by the
// spec loaders (L0) and any project-local extension discovery, then
// treated as immutable.
type Set struct {
	Frameworks    *Registry[core.Framework]
	Sources       *Registry[core.SourcePlugin]
	Rules         *Registry[core.Rule]
	EvidenceTypes *Registry[core.EvidenceType]
	Policies      *Registry[core.Policy]
}

// NewSet returns a Set with empty registries for each kind.
func NewSet() *Set {
	return &Set{
		Frameworks:    NewFrameworkRegistry(),
		Sources:       NewSourceRegistry(),
		Rules:         NewRuleRegistry(),
		EvidenceTypes: NewEvidenceTypeRegistry(),
		Policies:      NewPolicyRegistry(),
	}
}
