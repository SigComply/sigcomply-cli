package registry

import "fmt"

// Registry is a generic, populated-once-at-startup catalog keyed by ID.
// The CLI's loading sequence is: load in-binary specs → load project-
// local extensions → validate cross-references → freeze. Nothing
// mutates a Registry after that freeze; there is no hot-reload, no
// mid-run discovery, no runtime mutation.
//
// keyFn extracts the ID used as the lookup key. Different item types
// expose their ID differently (a method on an interface, a field on a
// struct); keyFn abstracts that so a single Registry implementation
// serves all five concrete registries in this package.
type Registry[T any] struct {
	items map[string]T
	keyFn func(T) string
}

// New constructs an empty Registry. The keyFn extracts the lookup key
// from each item registered.
func New[T any](keyFn func(T) string) *Registry[T] {
	return &Registry[T]{
		items: make(map[string]T),
		keyFn: keyFn,
	}
}

// Register adds an item to the registry. Returns an error if the key
// is empty or already registered — both are configuration errors that
// the orchestrator should turn into exit code 3.
func (r *Registry[T]) Register(item T) error {
	id := r.keyFn(item)
	if id == "" {
		return fmt.Errorf("registry: refused to register item with empty ID")
	}
	if _, exists := r.items[id]; exists {
		return fmt.Errorf("registry: duplicate ID %q", id)
	}
	r.items[id] = item
	return nil
}

// Lookup returns the item registered under id, or (zero, false).
func (r *Registry[T]) Lookup(id string) (T, bool) {
	item, ok := r.items[id]
	return item, ok
}

// All returns every registered item. Order is unspecified — callers
// that need deterministic order must sort the result themselves.
func (r *Registry[T]) All() []T {
	out := make([]T, 0, len(r.items))
	for _, v := range r.items {
		out = append(out, v)
	}
	return out
}

// Len returns the number of registered items.
func (r *Registry[T]) Len() int {
	return len(r.items)
}
