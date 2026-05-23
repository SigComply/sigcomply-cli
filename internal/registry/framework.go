package registry

import "github.com/sigcomply/sigcomply-cli/internal/core"

// NewFrameworkRegistry returns an empty registry of core.Framework
// keyed by Framework.ID().
func NewFrameworkRegistry() *Registry[core.Framework] {
	return New(func(f core.Framework) string { return f.ID() })
}
