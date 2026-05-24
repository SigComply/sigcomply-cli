// Package sources holds the process-global factory registry used to
// instantiate SourcePlugin values from project configuration. Each
// in-tree source package registers itself via init(); the orchestrator
// (cmd/sigcomply/check.go) iterates cfg.Sources and looks up the
// factory by ID without knowing which sources exist.
//
// This is the **only** seam a third party needs to add a custom source.
// Project-local plugins drop a package under .sigcomply/plugins/<id>/
// whose init() calls sources.Register; `sigcomply build` (M16)
// compiles them in alongside the in-tree set. There is no runtime
// plugin loading, no shared library, no DSL — extensibility happens at
// build time, by code.
//
// See docs/architecture/04-source-plugins.md §The plugin contract and
// docs/architecture/07-extensibility.md §Custom source plugins.
package sources

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// Env carries everything a Factory needs to instantiate a plugin. The
// fields are stable contracts between the orchestrator and every
// registered factory; factories pull what they need and ignore the
// rest.
//
// Config is the raw map from cfg.Sources[id] in the project YAML.
// Vault is the active core.Vault (some plugins, like manual.pdf, need
// it to fetch attachments). FrameworkExtras is an escape hatch for
// data that is framework-specific rather than project-specific (e.g.,
// the manual catalog the active framework provides); a key/value
// convention is documented in each consuming source's package doc.
type Env struct {
	Config          map[string]any
	Vault           core.Vault
	FrameworkExtras map[string]any
}

// Factory builds a configured plugin instance. It is invoked once per
// registered source ID at the start of every `sigcomply check` run.
// Errors here surface as configuration errors (exit code 3).
type Factory func(ctx context.Context, env Env) (core.SourcePlugin, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// RegisterFactory adds a factory under id. Intended to be called from
// a source package's init(). Duplicate IDs panic at process start —
// duplicates among in-tree plugins are a programming error, and a
// project-local plugin claiming a reserved ID is a misconfiguration
// the build should not let through.
func RegisterFactory(id string, f Factory) {
	if id == "" {
		panic("sources: RegisterFactory: empty ID")
	}
	if f == nil {
		panic("sources: RegisterFactory: nil factory for " + id)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := factories[id]; dup {
		panic("sources: duplicate factory registration for " + id)
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

// IDs returns every registered ID in sorted order. The orchestrator
// uses this to produce a helpful error when a project config names a
// source ID that isn't compiled into the binary.
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

// Build looks up id and invokes the factory. It is the single entry
// point cmd/sigcomply uses; nothing in cmd needs to know which source
// IDs exist. Unknown IDs return a clear error pointing at the
// project-local plugin path.
func Build(ctx context.Context, id string, env Env) (core.SourcePlugin, error) {
	f, ok := Lookup(id)
	if !ok {
		return nil, fmt.Errorf("source %q is not registered (compiled-in IDs: %v; "+
			"project-local plugins under .sigcomply/plugins/ are compiled in via `sigcomply build`)",
			id, IDs())
	}
	return f(ctx, env)
}

// reset is exported only for tests in this package. Production code
// never resets the registry.
func reset() {
	mu.Lock()
	defer mu.Unlock()
	factories = map[string]Factory{}
}

// StringOpt reads a string-valued entry from a YAML-unmarshaled map,
// returning "" when missing or the wrong type. Factories use it to
// pull values from Env.Config; the explicit two-step form avoids the
// `, _ := m[k].(string)` idiom (which our linter forbids under
// errcheck strict mode).
func StringOpt(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
