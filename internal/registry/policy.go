package registry

import "github.com/sigcomply/sigcomply-cli/internal/core"

// NewPolicyRegistry returns an empty registry of core.Policy keyed by
// Policy.ID. Framework-shipped policies and project-local custom
// policies share this registry; the loader at L0/L2 is responsible
// for merging both into the single namespace.
func NewPolicyRegistry() *Registry[core.Policy] {
	return New(func(p core.Policy) string { return p.ID })
}
