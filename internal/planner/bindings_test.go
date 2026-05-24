package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

type stubSource struct {
	id    string
	emits []string
}

func (s *stubSource) ID() string                                 { return s.id }
func (s *stubSource) Emits() []string                            { return s.emits }
func (s *stubSource) Init(context.Context, map[string]any) error { return nil }
func (s *stubSource) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, nil
}

func registerSource(t *testing.T, set *registry.Set, id string, emits ...string) {
	t.Helper()
	if err := set.Sources.Register(&stubSource{id: id, emits: emits}); err != nil {
		t.Fatalf("register %s: %v", id, err)
	}
}

func TestResolveBindings_ExactlyOne_RequiresOne(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "user_record")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"user_record"}, Cardinality: core.SlotExactlyOne, Required: true},
		},
	}
	cases := []struct {
		name      string
		entries   []spec.BindingEntry
		wantError string
	}{
		{"zero", nil, "exactly-one requires 1 binding, got 0"},
		{"two", []spec.BindingEntry{{Source: "aws.iam"}, {Source: "aws.iam"}}, "exactly-one requires 1 binding, got 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveBindings(policy, map[string][]spec.BindingEntry{"u": tc.entries}, set.Sources)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("want error containing %q; got %v", tc.wantError, err)
			}
		})
	}
}

func TestResolveBindings_AtMostOne(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "user_record")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"user_record"}, Cardinality: core.SlotAtMostOne, Required: false},
		},
	}
	// Zero is fine.
	if _, err := resolveBindings(policy, map[string][]spec.BindingEntry{"u": nil}, set.Sources); err != nil {
		t.Errorf("at-most-one with zero bindings: %v", err)
	}
	// Two is not.
	_, err := resolveBindings(policy, map[string][]spec.BindingEntry{
		"u": {{Source: "aws.iam"}, {Source: "aws.iam"}},
	}, set.Sources)
	if err == nil || !strings.Contains(err.Error(), "at-most-one") {
		t.Errorf("want at-most-one error; got %v", err)
	}
}

func TestResolveBindings_Optional(t *testing.T) {
	set := registry.NewSet()
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"user_record"}, Cardinality: core.SlotOptional, Required: false},
		},
	}
	bindings, err := resolveBindings(policy, nil, set.Sources)
	if err != nil {
		t.Fatalf("optional with zero bindings: %v", err)
	}
	if len(bindings["u"]) != 0 {
		t.Errorf("expected empty bindings; got %v", bindings["u"])
	}
}

func TestResolveBindings_ManualColonSuffixParsed(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "manual.pdf", "signed_document")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"doc": {Accepts: []string{"signed_document"}, Cardinality: core.SlotExactlyOne, Required: true},
		},
	}
	bindings, err := resolveBindings(policy, map[string][]spec.BindingEntry{
		"doc": {{Source: "manual.pdf:access_review_quarterly"}},
	}, set.Sources)
	if err != nil {
		t.Fatalf("resolveBindings: %v", err)
	}
	if bindings["doc"][0].SourceID != "manual.pdf" {
		t.Errorf("SourceID = %q; want manual.pdf", bindings["doc"][0].SourceID)
	}
	if bindings["doc"][0].CatalogID != "access_review_quarterly" {
		t.Errorf("CatalogID = %q; want access_review_quarterly", bindings["doc"][0].CatalogID)
	}
}

func TestResolveBindings_RejectsBindingForUndeclaredSlot(t *testing.T) {
	set := registry.NewSet()
	registerSource(t, set, "aws.iam", "user_record")
	policy := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"u": {Accepts: []string{"user_record"}, Cardinality: core.SlotOneOrMore, Required: true},
		},
	}
	_, err := resolveBindings(policy, map[string][]spec.BindingEntry{
		"u":            {{Source: "aws.iam"}},
		"phantom_slot": {{Source: "aws.iam"}},
	}, set.Sources)
	if err == nil || !strings.Contains(err.Error(), "phantom_slot") {
		t.Errorf("want unknown-slot error; got %v", err)
	}
}

func TestSplitCommaList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"  a , b ,c  ", []string{"a", "b", "c"}},
		{"a,,b", []string{"a", "b"}},
	}
	for _, tc := range cases {
		got := SplitCommaList(tc.in)
		if !equalStringSlices(got, tc.want) {
			t.Errorf("SplitCommaList(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
