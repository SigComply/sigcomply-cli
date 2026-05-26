package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func TestReadPolicyState_MissingShardReturnsNil(t *testing.T) {
	v := newInMem()
	got, err := ReadPolicyState(context.Background(), v, "soc2", "soc2.cc6.1.mfa")
	if err != nil {
		t.Fatalf("ReadPolicyState: %v", err)
	}
	if got != nil {
		t.Errorf("missing shard should return nil; got %+v", got)
	}
}

func TestReadPolicyState_ReadErrorPropagates(t *testing.T) {
	v := newInMem()
	v.getErr = errors.New("disk on fire") // does not contain "not found"
	_, err := ReadPolicyState(context.Background(), v, "soc2", "p1")
	if err == nil {
		t.Fatal("expected error from broken vault Get; got nil")
	}
}

func TestReadPolicyState_CorruptShardReturnsError(t *testing.T) {
	v := newInMem()
	v.bins[PolicyStatePath("soc2", "p1")] = []byte("not json at all")
	_, err := ReadPolicyState(context.Background(), v, "soc2", "p1")
	if err == nil {
		t.Fatal("expected parse error; got nil")
	}
}

func TestWritePolicyState_WritesAndRoundTrips(t *testing.T) {
	v := newInMem()
	at := time.Date(2026, 5, 24, 0, 3, 12, 0, time.UTC)
	ps := &core.PolicyState{
		Framework:       "soc2",
		PolicyID:        "soc2.cc6.1.mfa",
		LastRunAt:       at,
		LastPassAt:      at,
		LastRunStatus:   core.StatusPass,
		LastRunID:       "run-1",
		LastPolicyHash:  "sha256:abc",
		LastEnvelopeRef: "soc2/2026-Q2/run_X/policies/soc2.cc6.1.mfa/envelopes/x.json",
	}
	if err := WritePolicyState(context.Background(), v, ps); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Mirror the JSON write so subsequent GetBinary can find it.
	v.bins[PolicyStatePath("soc2", "soc2.cc6.1.mfa")] = v.jsons[PolicyStatePath("soc2", "soc2.cc6.1.mfa")]

	got, err := ReadPolicyState(context.Background(), v, "soc2", "soc2.cc6.1.mfa")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil state after write")
	}
	if !got.LastPassAt.Equal(at) {
		t.Errorf("LastPassAt = %v; want %v", got.LastPassAt, at)
	}
	if got.LastRunStatus != core.StatusPass {
		t.Errorf("LastRunStatus = %q; want pass", got.LastRunStatus)
	}
	if got.SchemaVersion != core.PolicyStateSchemaVersion {
		t.Errorf("SchemaVersion = %q; want %q", got.SchemaVersion, core.PolicyStateSchemaVersion)
	}
}

func TestWritePolicyState_MonotonicGuardRejectsOlderRun(t *testing.T) {
	v := newInMem()
	tEarly := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	tLate := tEarly.Add(2 * time.Hour)

	// Write the LATE state first.
	late := &core.PolicyState{
		Framework: "soc2", PolicyID: "p1",
		LastRunAt: tLate, LastRunID: "run-late",
		LastRunStatus: core.StatusPass, LastPassAt: tLate,
	}
	if err := WritePolicyState(context.Background(), v, late); err != nil {
		t.Fatalf("write late: %v", err)
	}
	v.bins[PolicyStatePath("soc2", "p1")] = v.jsons[PolicyStatePath("soc2", "p1")]

	// Try to write the EARLY state — should be rejected silently.
	early := &core.PolicyState{
		Framework: "soc2", PolicyID: "p1",
		LastRunAt: tEarly, LastRunID: "run-early",
		LastRunStatus: core.StatusFail, LastFailAt: tEarly,
	}
	if err := WritePolicyState(context.Background(), v, early); err != nil {
		t.Fatalf("write early returned error (should be silently rejected): %v", err)
	}
	// Re-read: must still see LATE.
	v.bins[PolicyStatePath("soc2", "p1")] = v.jsons[PolicyStatePath("soc2", "p1")]
	got, err := ReadPolicyState(context.Background(), v, "soc2", "p1")
	if err != nil {
		t.Fatalf("read after rejected write: %v", err)
	}
	if got.LastRunID != "run-late" {
		t.Errorf("LastRunID = %q; monotonic guard should have preserved run-late", got.LastRunID)
	}
}

func TestWritePolicyState_RunIDTiebreakOnExactTimestamp(t *testing.T) {
	v := newInMem()
	tEq := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)

	// Write run-AAA first.
	a := &core.PolicyState{Framework: "soc2", PolicyID: "p1",
		LastRunAt: tEq, LastRunID: "run-AAA", LastRunStatus: core.StatusPass, LastPassAt: tEq}
	if err := WritePolicyState(context.Background(), v, a); err != nil {
		t.Fatalf("write A: %v", err)
	}
	v.bins[PolicyStatePath("soc2", "p1")] = v.jsons[PolicyStatePath("soc2", "p1")]

	// run-ZZZ with same timestamp sorts higher → wins.
	z := &core.PolicyState{Framework: "soc2", PolicyID: "p1",
		LastRunAt: tEq, LastRunID: "run-ZZZ", LastRunStatus: core.StatusPass, LastPassAt: tEq}
	if err := WritePolicyState(context.Background(), v, z); err != nil {
		t.Fatalf("write Z: %v", err)
	}
	v.bins[PolicyStatePath("soc2", "p1")] = v.jsons[PolicyStatePath("soc2", "p1")]
	got, err := ReadPolicyState(context.Background(), v, "soc2", "p1")
	if err != nil {
		t.Fatalf("read after tiebreaker: %v", err)
	}
	if got.LastRunID != "run-ZZZ" {
		t.Errorf("tiebreaker lost: LastRunID = %q; want run-ZZZ", got.LastRunID)
	}
}

func TestWritePolicyState_RejectsEmptyFields(t *testing.T) {
	v := newInMem()
	if err := WritePolicyState(context.Background(), v, &core.PolicyState{}); err == nil {
		t.Fatal("expected error for empty PolicyID/Framework")
	}
}

func TestBulkReadPolicyStates_HandlesMixedPresence(t *testing.T) {
	v := newInMem()
	at := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	ps := &core.PolicyState{Framework: "soc2", PolicyID: "have",
		LastRunAt: at, LastRunID: "r", LastRunStatus: core.StatusPass, LastPassAt: at}
	if err := WritePolicyState(context.Background(), v, ps); err != nil {
		t.Fatalf("seed: %v", err)
	}
	v.bins[PolicyStatePath("soc2", "have")] = v.jsons[PolicyStatePath("soc2", "have")]

	got, errs := BulkReadPolicyStates(context.Background(), v, "soc2",
		[]string{"have", "missing"})
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if got["have"] == nil {
		t.Errorf("present policy returned nil")
	}
	if got["missing"] != nil {
		t.Errorf("missing policy should be nil entry; got %+v", got["missing"])
	}
}

func TestAdvancePolicyState_PassSetsLastPassAndNextDue(t *testing.T) {
	startedAt := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	interval := 6 * time.Hour
	ps := AdvancePolicyState("soc2", "p1", "run-1", "2026-Q2", "every:6h", "sha256:x", "vault/envelopes/x.json",
		core.StatusPass, startedAt, interval)
	if !ps.LastPassAt.Equal(startedAt) {
		t.Errorf("LastPassAt = %v; want %v", ps.LastPassAt, startedAt)
	}
	if ps.LastFailAt != (time.Time{}) {
		t.Errorf("LastFailAt should be zero for pass; got %v", ps.LastFailAt)
	}
	want := startedAt.Add(interval).UTC()
	if !ps.NextDueAt.Equal(want) {
		t.Errorf("NextDueAt = %v; want %v", ps.NextDueAt, want)
	}
}

func TestAdvancePolicyState_FailSetsLastFailAndNoNextDue(t *testing.T) {
	startedAt := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	ps := AdvancePolicyState("soc2", "p1", "run-1", "2026-Q2", "daily", "sha256:x", "vault/x.json",
		core.StatusFail, startedAt, 24*time.Hour)
	if !ps.LastFailAt.Equal(startedAt) {
		t.Errorf("LastFailAt = %v", ps.LastFailAt)
	}
	if !ps.NextDueAt.IsZero() {
		t.Errorf("NextDueAt should be zero for non-pass (on_fail_retry); got %v", ps.NextDueAt)
	}
}

func TestPolicyStatePath_Shape(t *testing.T) {
	got := PolicyStatePath("soc2", "soc2.cc6.1.mfa_enforced")
	want := "state/soc2/policies/soc2.cc6.1.mfa_enforced.json"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}
