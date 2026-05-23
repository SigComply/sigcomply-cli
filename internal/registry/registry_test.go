package registry

import (
	"sort"
	"testing"
)

// keyOf is the trivial identity keyFn used by these tests — the item
// type is string, and the ID is the string itself.
func keyOf(s string) string { return s }

func TestRegistry_RegisterAndLookup(t *testing.T) {
	r := New(keyOf)
	if err := r.Register("alpha"); err != nil {
		t.Fatalf("Register(alpha): %v", err)
	}
	got, ok := r.Lookup("alpha")
	if !ok || got != "alpha" {
		t.Errorf("Lookup(alpha) = (%q, %v); want (alpha, true)", got, ok)
	}
}

func TestRegistry_LookupMiss(t *testing.T) {
	r := New(keyOf)
	if _, ok := r.Lookup("nope"); ok {
		t.Error("Lookup of unregistered id returned ok=true")
	}
}

func TestRegistry_DuplicateRejected(t *testing.T) {
	r := New(keyOf)
	if err := r.Register("alpha"); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := r.Register("alpha"); err == nil {
		t.Error("Register of duplicate id returned nil error")
	}
}

func TestRegistry_EmptyIDRejected(t *testing.T) {
	r := New(keyOf)
	if err := r.Register(""); err == nil {
		t.Error("Register with empty id returned nil error")
	}
}

func TestRegistry_AllAndLen(t *testing.T) {
	r := New(keyOf)
	items := []string{"a", "b", "c"}
	for _, x := range items {
		if err := r.Register(x); err != nil {
			t.Fatalf("Register(%q): %v", x, err)
		}
	}
	if got := r.Len(); got != 3 {
		t.Errorf("Len = %d; want 3", got)
	}
	all := r.All()
	sort.Strings(all)
	for i, want := range items {
		if all[i] != want {
			t.Errorf("All[%d] = %q; want %q", i, all[i], want)
		}
	}
}
