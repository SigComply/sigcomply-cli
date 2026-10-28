// Package vault's registry is the seam every storage backend plugs
// into. Each in-tree backend (local, s3, gcs, azure_blob) self-registers
// from its package init(); the orchestrator pulls them in via the
// vault/builtin blank-import package. Third-party backends (SFTP,
// MinIO, on-prem NFS, custom object stores) follow the same pattern
// from a project-local plugin compiled in by `sigcomply build` (M16).
// FromConfig knows nothing about which backends exist.
//
// This mirrors the source-plugin registry in internal/sources/factory.go
// — see docs/architecture/00-three-plugin-axes.md §Axis B (Output
// Vault Storage) for the unified design rationale.

package vault

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Factory builds a fully Init'd Vault from the project's vault config.
// Backends translate from spec.VaultConfig to their own Options struct,
// call New, and Init before returning.
type Factory func(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
	keys      = map[string][]string{}
)

// RegisterBackendKeys records the config keys a backend reads besides
// `backend`, so ConfigWarnings can name a mistyped one. Optional: a
// backend that registers none is never warned about, which keeps a
// project-local backend unaffected.
func RegisterBackendKeys(id string, configKeys ...string) {
	mu.Lock()
	defer mu.Unlock()
	keys[id] = append([]string(nil), configKeys...)
}

// ConfigWarnings reports vault keys the configured backend does not
// read. The vault block is an open bag, so `bakend: s3` used to load
// with no word and the run wrote to the default local folder.
//
// Warning, never error: the same tolerance the sources: block has.
func ConfigWarnings(cfg *spec.VaultConfig) []string {
	if cfg == nil {
		return nil
	}
	mu.RLock()
	known := keys[cfg.Backend]
	mu.RUnlock()
	if len(known) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(known))
	for _, k := range known {
		set[k] = struct{}{}
	}
	names := make([]string, 0, len(cfg.Config))
	for k := range cfg.Config {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []string
	for _, k := range names {
		if _, ok := set[k]; !ok {
			out = append(out, fmt.Sprintf("vault: unrecognized key %q, so it was ignored; backend %q reads %v", k, cfg.Backend, known))
		}
	}
	return out
}

// RegisterBackend adds a Factory under id. Intended for an init() call
// in the backend's package. Duplicate IDs panic at process start —
// duplicates among in-tree backends are a programming error, and a
// project-local backend claiming a reserved ID is a misconfiguration
// the build should not let through.
func RegisterBackend(id string, f Factory) {
	if id == "" {
		panic("vault: RegisterBackend: empty ID")
	}
	if f == nil {
		panic("vault: RegisterBackend: nil factory for " + id)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := factories[id]; dup {
		panic("vault: duplicate backend registration for " + id)
	}
	factories[id] = f
}

// Lookup returns the factory registered under id, or (nil, false).
func Lookup(id string) (Factory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := factories[id]
	return f, ok
}

// IDs returns every registered backend ID in sorted order. Used to
// build helpful error messages when project config names an unknown
// backend.
func IDs() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(factories))
	for id := range factories {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
