package registry

import "github.com/sigcomply/sigcomply-cli/internal/core"

// NewRuleRegistry returns an empty registry of core.Rule keyed by
// Rule.ID() — the dotted-with-version reference (rules.<name>.v<n>)
// that policy specs declare via their `rule:` field.
func NewRuleRegistry() *Registry[core.Rule] {
	return New(func(r core.Rule) string { return r.ID() })
}
