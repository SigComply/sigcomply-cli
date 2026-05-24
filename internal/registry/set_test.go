package registry

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func TestNewSet_AllRegistriesEmpty(t *testing.T) {
	s := NewSet()
	if s.Frameworks == nil || s.Sources == nil || s.Rules == nil ||
		s.EvidenceTypes == nil || s.Policies == nil {
		t.Fatal("NewSet returned a nil sub-registry")
	}
	for name, n := range map[string]int{
		"Frameworks":    s.Frameworks.Len(),
		"Sources":       s.Sources.Len(),
		"Rules":         s.Rules.Len(),
		"EvidenceTypes": s.EvidenceTypes.Len(),
		"Policies":      s.Policies.Len(),
	} {
		if n != 0 {
			t.Errorf("%s registry not empty after NewSet: %d items", name, n)
		}
	}
}

// stubs exercise each typed registry's generic instantiation.

type stubFramework struct{ id string }

func (s stubFramework) ID() string               { return s.id }
func (stubFramework) Version() string            { return "1" }
func (stubFramework) Controls() []core.Control   { return nil }
func (stubFramework) Policies() []core.PolicyRef { return nil }

type stubSource struct{ id string }

func (s stubSource) ID() string                               { return s.id }
func (stubSource) Emits() []string                            { return nil }
func (stubSource) Init(context.Context, map[string]any) error { return nil }
func (stubSource) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, nil
}

type stubRule struct{ id string }

func (s stubRule) ID() string { return s.id }
func (stubRule) Evaluate(context.Context, core.RuleInput) (core.RuleResult, error) {
	return core.RuleResult{Status: core.StatusPass}, nil
}

func TestSet_RegisterAndLookupEachKind(t *testing.T) {
	s := NewSet()

	if err := s.Frameworks.Register(stubFramework{id: "fw"}); err != nil {
		t.Fatalf("Frameworks.Register: %v", err)
	}
	if err := s.Sources.Register(stubSource{id: "src"}); err != nil {
		t.Fatalf("Sources.Register: %v", err)
	}
	if err := s.Rules.Register(stubRule{id: "rules.fake.v1"}); err != nil {
		t.Fatalf("Rules.Register: %v", err)
	}
	if err := s.EvidenceTypes.Register(core.EvidenceType{
		ID:      "user_record",
		Version: 1,
		Schema:  json.RawMessage(`{}`),
	}); err != nil {
		t.Fatalf("EvidenceTypes.Register: %v", err)
	}
	if err := s.Policies.Register(core.Policy{ID: "soc2.cc6.1.mfa_enforced"}); err != nil {
		t.Fatalf("Policies.Register: %v", err)
	}

	checks := []struct {
		name string
		ok   bool
	}{
		{"Frameworks", lookupOK(s.Frameworks.Lookup("fw"))},
		{"Sources", lookupOK(s.Sources.Lookup("src"))},
		{"Rules", lookupOK(s.Rules.Lookup("rules.fake.v1"))},
		{"EvidenceTypes", lookupOK(s.EvidenceTypes.Lookup("user_record"))},
		{"Policies", lookupOK(s.Policies.Lookup("soc2.cc6.1.mfa_enforced"))},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("%s.Lookup miss after Register", c.name)
		}
	}
}

func lookupOK[T any](_ T, ok bool) bool { return ok }
