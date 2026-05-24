package sources

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakePlugin struct {
	id    string
	emits []string
}

func (p *fakePlugin) ID() string                                 { return p.id }
func (p *fakePlugin) Emits() []string                            { return p.emits }
func (p *fakePlugin) Init(context.Context, map[string]any) error { return nil }
func (p *fakePlugin) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, nil
}

func TestRegisterAndLookup(t *testing.T) {
	t.Cleanup(reset)
	reset()
	RegisterFactory("acme.test", func(context.Context, Env) (core.SourcePlugin, error) {
		return &fakePlugin{id: "acme.test", emits: []string{"acme_thing"}}, nil
	})
	f, ok := Lookup("acme.test")
	if !ok || f == nil {
		t.Fatal("expected factory after Register")
	}
	plugin, err := f(context.Background(), Env{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if plugin.ID() != "acme.test" {
		t.Errorf("plugin.ID = %q", plugin.ID())
	}
}

func TestRegister_RejectsEmptyID(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on empty ID")
		}
	}()
	RegisterFactory("", func(context.Context, Env) (core.SourcePlugin, error) { return nil, nil })
}

func TestRegister_RejectsNilFactory(t *testing.T) {
	t.Cleanup(reset)
	reset()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil factory")
		}
	}()
	RegisterFactory("acme.nil", nil)
}

func TestRegister_RejectsDuplicate(t *testing.T) {
	t.Cleanup(reset)
	reset()
	f := func(context.Context, Env) (core.SourcePlugin, error) { return &fakePlugin{}, nil }
	RegisterFactory("acme.dup", f)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate ID")
		}
	}()
	RegisterFactory("acme.dup", f)
}

func TestBuild_UnknownIDError(t *testing.T) {
	t.Cleanup(reset)
	reset()
	RegisterFactory("acme.known", func(context.Context, Env) (core.SourcePlugin, error) {
		return &fakePlugin{}, nil
	})
	_, err := Build(context.Background(), "nope.unknown", Env{})
	if err == nil {
		t.Fatal("expected error for unknown ID")
	}
	if !strings.Contains(err.Error(), "is not registered") {
		t.Errorf("error = %v; want is-not-registered phrasing", err)
	}
	if !strings.Contains(err.Error(), "acme.known") {
		t.Errorf("error = %v; want to mention known IDs", err)
	}
}

func TestBuild_PropagatesFactoryError(t *testing.T) {
	t.Cleanup(reset)
	reset()
	want := errors.New("boom")
	RegisterFactory("acme.bad", func(context.Context, Env) (core.SourcePlugin, error) {
		return nil, want
	})
	_, err := Build(context.Background(), "acme.bad", Env{})
	if !errors.Is(err, want) {
		t.Errorf("err = %v; want %v", err, want)
	}
}

func TestIDs_SortedAndComplete(t *testing.T) {
	t.Cleanup(reset)
	reset()
	for _, id := range []string{"c.three", "a.one", "b.two"} {
		RegisterFactory(id, func(context.Context, Env) (core.SourcePlugin, error) { return &fakePlugin{}, nil })
	}
	got := IDs()
	want := []string{"a.one", "b.two", "c.three"}
	if len(got) != len(want) {
		t.Fatalf("IDs() = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("IDs()[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}
