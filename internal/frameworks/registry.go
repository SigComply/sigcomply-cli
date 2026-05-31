// Package frameworks holds the process-global registry of compliance
// framework factories. Each in-tree framework (soc2, iso27001, …)
// registers its Factory from package init(); commands look the factory
// up by the configured framework ID and never branch on it directly.
//
// This mirrors the source-plugin (internal/sources) and vault-backend
// (internal/vault) factory models: adding a framework is dropping a
// package under internal/frameworks/<id>/ with an init() that calls
// RegisterFactory, then adding one blank import to
// internal/frameworks/builtin. cmd/sigcomply needs no change.
package frameworks

import (
	"fmt"
	"sort"
	"sync"

	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// Factory wires one framework into a run. Register populates the
// framework, rule, and policy registries (it is the framework's own
// Register function). ManualCatalog returns the framework's
// manual-evidence catalog — an empty map when the framework has no
// manual policies.
type Factory struct {
	Register      func(*registry.Set) error
	ManualCatalog func() map[string]manual.CatalogEntry
}

var (
	mu        sync.Mutex
	factories = map[string]Factory{}
)

// RegisterFactory adds a framework factory under id. Intended to be
// called from a framework package's init(). Panics on duplicate or
// empty id — a programming error that must fail loudly at startup.
func RegisterFactory(id string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if id == "" {
		panic("frameworks: empty framework id")
	}
	if _, dup := factories[id]; dup {
		panic(fmt.Sprintf("frameworks: duplicate framework registration for %q", id))
	}
	factories[id] = f
}

// Lookup returns the factory registered for id.
func Lookup(id string) (Factory, bool) {
	mu.Lock()
	defer mu.Unlock()
	f, ok := factories[id]
	return f, ok
}

// IDs returns the sorted list of registered framework IDs, used for
// error messages that enumerate supported frameworks.
func IDs() []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(factories))
	for id := range factories {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
