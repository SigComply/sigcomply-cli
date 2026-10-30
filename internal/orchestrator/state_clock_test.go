package orchestrator

import (
	"context"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// stampField sets one of a shard's "when did this happen" fields.
var stampFields = map[string]func(*core.PolicyState, time.Time){
	"last_run_at":  func(s *core.PolicyState, t time.Time) { s.LastRunAt = t },
	"last_pass_at": func(s *core.PolicyState, t time.Time) { s.LastPassAt = t },
	"last_fail_at": func(s *core.PolicyState, t time.Time) { s.LastFailAt = t },
}

// passingShard is a state shard that says the policy passed at `at`,
// so an annual policy would be carried forward for a year.
func passingShard(at time.Time) *core.PolicyState {
	return &core.PolicyState{
		SchemaVersion: core.PolicyStateSchemaVersion,
		Framework:     testFramework, PolicyID: "p1",
		LastRunAt: at, LastPassAt: at, LastRunStatus: core.StatusPass, LastRunID: "forged",
	}
}

func loadOne(t *testing.T, v *listVault, now time.Time) (state *core.PolicyState, logs string) {
	t.Helper()
	regs := registry.NewSet()
	if err := regs.Frameworks.Register(&stateFramework{policies: []core.PolicyRef{{PolicyID: "p1"}}}); err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	opts := &Options{
		Config:     &spec.ProjectConfig{Framework: testFramework},
		Registries: regs,
		Vault:      v,
		Logger:     log.New(&buf, false),
		Now:        func() time.Time { return now },
	}
	return loadPolicyStates(context.Background(), opts)["p1"], buf.String()
}

// TestLoadPolicyStates_FutureShardForcesEvaluation is a property test
// over random offsets: state shards are unsigned, so anyone who can
// write the vault could plant a shard whose timestamps lie in the
// future. A pass dated next year made an annual policy carry forward
// without being evaluated, and a run date in the future froze the shard
// (the monotonic write guard refused every honest write). Any shard
// with a timestamp later than the run clock plus stateClockSkew is
// corrupt: the policy is treated as never run, so it is evaluated.
func TestLoadPolicyStates_FutureShardForcesEvaluation(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test data
	for field, set := range stampFields {
		for i := 0; i < 50; i++ {
			ahead := stateClockSkew + time.Second + time.Duration(rng.Int63n(int64(100*365*24*time.Hour)))
			v := newListVault()
			s := passingShard(now.Add(-time.Hour))
			set(s, now.Add(ahead))
			if err := v.PutJSON(context.Background(), PolicyStatePath(testFramework, "p1"), s); err != nil {
				t.Fatal(err)
			}
			got, logs := loadOne(t, v, now)
			if got != nil {
				t.Fatalf("%s %v ahead of the run clock: shard loaded; want it treated as corrupt", field, ahead)
			}
			if !planner.IsDue(cadenceAnnualForTest, got, now) {
				t.Fatalf("%s %v ahead: policy not due; want it evaluated", field, ahead)
			}
			if !strings.Contains(logs, "p1") || !strings.Contains(logs, "future") {
				t.Fatalf("no warning naming the policy and the future timestamp; logs: %q", logs)
			}
		}
	}
}

const cadenceAnnualForTest = "annual"

// Within the allowed clock skew a shard is honest: runners' clocks
// differ by seconds, and a shard written by a runner slightly ahead
// must still carry its pass forward.
func TestLoadPolicyStates_ShardWithinSkewIsKept(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	v := newListVault()
	s := passingShard(now.Add(stateClockSkew))
	if err := v.PutJSON(context.Background(), PolicyStatePath(testFramework, "p1"), s); err != nil {
		t.Fatal(err)
	}
	got, _ := loadOne(t, v, now)
	if got == nil {
		t.Fatal("shard within the skew was dropped")
	}
	if planner.IsDue(cadenceAnnualForTest, got, now) {
		t.Error("an annual policy that passed just now is due again")
	}
}

// WritePolicyState replaces a future-dated shard instead of letting the
// monotonic guard keep it forever.
func TestWritePolicyState_ReplacesFutureDatedShard(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	v := newListVault()
	if err := v.PutJSON(context.Background(), PolicyStatePath(testFramework, "p1"),
		passingShard(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))); err != nil {
		t.Fatal(err)
	}
	honest := &core.PolicyState{
		Framework: testFramework, PolicyID: "p1",
		LastRunAt: now, LastFailAt: now, LastRunStatus: core.StatusFail, LastRunID: "run-honest",
	}
	if err := WritePolicyState(context.Background(), v, honest, now); err != nil {
		t.Fatalf("WritePolicyState: %v", err)
	}
	got, err := ReadPolicyState(context.Background(), v, testFramework, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRunID != "run-honest" {
		t.Errorf("LastRunID = %q; the future-dated shard should have been replaced", got.LastRunID)
	}
}
