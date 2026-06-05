package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// listVault is an in-memory vault that actually implements List and
// persists PutJSON bytes so they can be read back via GetBinary — the
// minimum needed to exercise ListPolicyStates and loadPolicyStates,
// which the bare inMemVault (no List, no JSON→bin mirroring) cannot.
type listVault struct {
	data    map[string][]byte
	listErr error
}

func newListVault() *listVault { return &listVault{data: map[string][]byte{}} }

func (v *listVault) Init(context.Context) error { return nil }
func (v *listVault) PutEnvelope(context.Context, string, *core.Envelope) error {
	return nil
}
func (v *listVault) PutJSON(_ context.Context, k string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	v.data[k] = b
	return nil
}
func (v *listVault) PutBinary(_ context.Context, k string, body []byte, _ map[string]string) error {
	v.data[k] = body
	return nil
}
func (v *listVault) GetBinary(_ context.Context, k string) ([]byte, error) {
	if b, ok := v.data[k]; ok {
		return b, nil
	}
	return nil, errors.New("vault: not found")
}
func (v *listVault) List(_ context.Context, prefix string) ([]string, error) {
	if v.listErr != nil {
		return nil, v.listErr
	}
	var out []string
	for k := range v.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func seedState(t *testing.T, v *listVault, framework, policyID string, at time.Time) {
	t.Helper()
	ps := &core.PolicyState{
		SchemaVersion: core.PolicyStateSchemaVersion,
		Framework:     framework, PolicyID: policyID,
		LastRunAt: at, LastPassAt: at, LastRunStatus: core.StatusPass, LastRunID: "seed",
	}
	if err := WritePolicyState(context.Background(), v, ps); err != nil {
		t.Fatalf("seed %s: %v", policyID, err)
	}
}

func TestPolicyStatePrefix_Shape(t *testing.T) {
	if got := PolicyStatePrefix("soc2"); got != "state/soc2/policies/" {
		t.Errorf("PolicyStatePrefix = %q", got)
	}
}

func TestListPolicyStates_EnumeratesShards(t *testing.T) {
	v := newListVault()
	at := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	seedState(t, v, "soc2", "soc2.cc6.1.mfa", at)
	seedState(t, v, "soc2", "soc2.cc7.2.logging", at)
	// A non-shard key under the same prefix must be skipped.
	v.data["state/soc2/policies/README.txt"] = []byte("ignore me")

	got, err := ListPolicyStates(context.Background(), v, "soc2")
	if err != nil {
		t.Fatalf("ListPolicyStates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d shards; want 2 (%v)", len(got), keysOf(got))
	}
	if got["soc2.cc6.1.mfa"] == nil || got["soc2.cc7.2.logging"] == nil {
		t.Errorf("expected both shards present: %v", keysOf(got))
	}
}

func TestListPolicyStates_NilVaultErrors(t *testing.T) {
	if _, err := ListPolicyStates(context.Background(), nil, "soc2"); err == nil {
		t.Error("want nil-vault error")
	}
}

func TestListPolicyStates_ListErrorPropagates(t *testing.T) {
	v := newListVault()
	v.listErr = errors.New("backend down")
	if _, err := ListPolicyStates(context.Background(), v, "soc2"); err == nil {
		t.Error("want list error to propagate")
	}
}

// policyIDFromStatePath returns "" for keys that don't conform.
func TestPolicyIDFromStatePath(t *testing.T) {
	prefix := "state/soc2/policies/"
	cases := []struct {
		key  string
		want string
	}{
		{"state/soc2/policies/p1.json", "p1"},
		{"state/soc2/policies/soc2.cc6.1.mfa.json", "soc2.cc6.1.mfa"},
		{"state/soc2/policies/notjson.txt", ""},
		{"state/other/policies/p1.json", ""}, // wrong prefix
	}
	for _, c := range cases {
		if got := policyIDFromStatePath(prefix, c.key); got != c.want {
			t.Errorf("policyIDFromStatePath(%q) = %q; want %q", c.key, got, c.want)
		}
	}
}

// loadPolicyStates returns an empty map when the framework is not
// registered (degrades to "treat as first run").
func TestLoadPolicyStates_UnregisteredFramework(t *testing.T) {
	opts := &Options{
		Config:     &spec.ProjectConfig{Framework: "soc2"},
		Registries: registry.NewSet(), // no framework registered
		Vault:      newListVault(),
		Logger:     log.New(&strings.Builder{}, false),
	}
	got := loadPolicyStates(context.Background(), opts)
	if len(got) != 0 {
		t.Errorf("want empty map for unregistered framework; got %v", keysOf(got))
	}
}

// loadPolicyStates reads one shard per policy the framework declares.
func TestLoadPolicyStates_ReadsRegisteredPolicies(t *testing.T) {
	v := newListVault()
	at := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	seedState(t, v, "soc2", "p1", at)
	// p2 has no shard → present-but-nil in the result.

	regs := registry.NewSet()
	if err := regs.Frameworks.Register(&stateFramework{
		policies: []core.PolicyRef{{PolicyID: "p1"}, {PolicyID: "p2"}},
	}); err != nil {
		t.Fatal(err)
	}
	opts := &Options{
		Config:     &spec.ProjectConfig{Framework: "soc2"},
		Registries: regs,
		Vault:      v,
		Logger:     log.New(&strings.Builder{}, false),
	}
	got := loadPolicyStates(context.Background(), opts)
	if got["p1"] == nil {
		t.Errorf("p1 shard should be loaded")
	}
	if _, present := got["p2"]; !present {
		t.Errorf("p2 should be present-but-nil (never run)")
	}
	if got["p2"] != nil {
		t.Errorf("p2 should be nil (no shard); got %+v", got["p2"])
	}
}

// stateFramework is a tiny framework stub for the state-load tests.
type stateFramework struct {
	policies []core.PolicyRef
}

func (*stateFramework) ID() string                   { return "soc2" }
func (*stateFramework) Version() string              { return "v0" }
func (*stateFramework) Controls() []core.Control     { return nil }
func (f *stateFramework) Policies() []core.PolicyRef { return f.policies }

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
