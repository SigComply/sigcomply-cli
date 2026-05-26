package evidencetypes

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

type fakeSource struct {
	id    string
	emits []string
}

func (f *fakeSource) ID() string                                 { return f.id }
func (f *fakeSource) Emits() []string                            { return f.emits }
func (f *fakeSource) Init(context.Context, map[string]any) error { return nil }
func (f *fakeSource) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, nil
}

func TestVerifyRegistrations_HappyPath(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := set.Sources.Register(&fakeSource{id: "aws.iam", emits: []string{"directory_user"}}); err != nil {
		t.Fatalf("Sources.Register: %v", err)
	}
	if err := set.Policies.Register(core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"users": {Accepts: []string{"directory_user"}},
		},
	}); err != nil {
		t.Fatalf("Policies.Register: %v", err)
	}
	if err := VerifyRegistrations(set); err != nil {
		t.Fatalf("VerifyRegistrations: %v", err)
	}
}

func TestVerifyRegistrations_RejectsSourceEmittingUnknownType(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := set.Sources.Register(&fakeSource{id: "weird", emits: []string{"unregistered_type"}}); err != nil {
		t.Fatalf("Sources.Register: %v", err)
	}
	err := VerifyRegistrations(set)
	if err == nil {
		t.Fatal("expected error for source emitting an unregistered type")
	}
	if !strings.Contains(err.Error(), "weird") || !strings.Contains(err.Error(), "unregistered_type") {
		t.Errorf("error should name the offending source and type; got %v", err)
	}
}

func TestVerifyRegistrations_RejectsPolicyAcceptingUnknownType(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := set.Policies.Register(core.Policy{
		ID: "p2",
		Slots: map[string]core.Slot{
			"data": {Accepts: []string{"ghost_type"}},
		},
	}); err != nil {
		t.Fatalf("Policies.Register: %v", err)
	}
	err := VerifyRegistrations(set)
	if err == nil {
		t.Fatal("expected error for policy slot.accepts referencing an unregistered type")
	}
	if !strings.Contains(err.Error(), "p2") || !strings.Contains(err.Error(), "ghost_type") {
		t.Errorf("error should name the offending policy and type; got %v", err)
	}
}

func TestVerifyRegistrations_RejectsNilSet(t *testing.T) {
	if err := VerifyRegistrations(nil); err == nil {
		t.Fatal("expected error on nil set")
	}
}
