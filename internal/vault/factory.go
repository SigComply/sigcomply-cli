package vault

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// FromConfig constructs the right backend for the given project-config
// vault section. The returned Vault is already Init'd and ready for
// Put/Get/List. The factory layer is L7's seam to L8 (Orchestrator):
// every other layer takes a core.Vault and doesn't care which backend
// is behind it.
//
// Backend selection goes through the package-global registry: each
// in-tree backend registers itself via init(), and the orchestrator
// blank-imports internal/vault/builtin to pull them all in. Third
// parties add custom backends the same way — see
// docs/architecture/07-extensibility.md §Custom vault backends.
func FromConfig(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
	if cfg.Backend == "" {
		return nil, fmt.Errorf("vault: backend not set in config")
	}
	f, ok := Lookup(cfg.Backend)
	if !ok {
		return nil, fmt.Errorf("vault: unsupported backend %q (compiled-in: %v; "+
			"third-party backends are compiled in via `sigcomply build`)", cfg.Backend, IDs())
	}
	return f(ctx, cfg)
}
