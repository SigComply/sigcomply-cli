package registry

import "github.com/sigcomply/sigcomply-cli/internal/core"

// NewSourceRegistry returns an empty registry of core.SourcePlugin
// keyed by SourcePlugin.ID().
func NewSourceRegistry() *Registry[core.SourcePlugin] {
	return New(func(s core.SourcePlugin) string { return s.ID() })
}
