package aggregator

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// A zero NextDueAt (continuous cadence / non-pass terminal status) must
// be OMITTED from the wire, never serialized as "0001-01-01T00:00:00Z".
// encoding/json's omitempty does not omit a zero time.Time struct, so
// the field is a *time.Time set to nil when zero. Rails would otherwise
// store a year-1 timestamp and render every such policy as permanently
// "stale". Same guard for a zero LastEvaluatedAt (nil Environment).
func TestBuild_ZeroCadenceTimes_OmittedFromWire(t *testing.T) {
	runStart := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	results := []core.PolicyResult{{
		PolicyID: "p1",
		Status:   core.StatusPass,
		// NextDueAt left zero (e.g. continuous cadence).
	}}
	got := Build(results, &Environment{StartedAt: runStart})
	ap := got.Policies[0]

	// A populated LastEvaluatedAt (run start) is present...
	if ap.LastEvaluatedAt == nil || !ap.LastEvaluatedAt.Equal(runStart) {
		t.Errorf("LastEvaluatedAt = %v; want %v", ap.LastEvaluatedAt, runStart)
	}
	// ...but a zero NextDueAt is nil, so it drops off the wire.
	if ap.NextDueAt != nil {
		t.Errorf("NextDueAt = %v; want nil for a zero time", ap.NextDueAt)
	}

	b, err := json.Marshal(ap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wire := string(b)
	if strings.Contains(wire, "0001-01-01") {
		t.Errorf("per-policy wire contains a zero-value year-1 timestamp:\n%s", wire)
	}
	if strings.Contains(wire, "next_due_at") {
		t.Errorf("zero next_due_at should be omitted, got:\n%s", wire)
	}
}

// For a carried-forward policy, LastEvaluatedAt comes from the
// carry-forward ref (the earlier run it inherits from), NOT the current
// run's StartedAt. IsCarriedForward must be true.
func TestBuild_CarriedForward_LastEvaluatedAtFromRef(t *testing.T) {
	priorEval := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	runStart := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	results := []core.PolicyResult{{
		PolicyID: "p1",
		Status:   core.StatusCarriedForward,
		CarryForward: &core.CarryForwardRef{
			LastEvaluatedAt: priorEval,
			LastEnvelopeRef: "soc2/2026-Q1/run_x/policies/p1/envelopes/e.json",
		},
	}}
	got := Build(results, &Environment{StartedAt: runStart})
	ap := got.Policies[0]
	if !ap.IsCarriedForward {
		t.Error("IsCarriedForward = false; want true")
	}
	if ap.LastEvaluatedAt == nil || !ap.LastEvaluatedAt.Equal(priorEval) {
		t.Errorf("LastEvaluatedAt = %v; want prior eval %v (not run start)", ap.LastEvaluatedAt, priorEval)
	}
}

// A freshly-evaluated policy's LastEvaluatedAt is the run's StartedAt.
func TestBuild_FreshlyEvaluated_LastEvaluatedAtFromRunStart(t *testing.T) {
	runStart := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	results := []core.PolicyResult{{PolicyID: "p1", Status: core.StatusPass}}
	got := Build(results, &Environment{StartedAt: runStart})
	if got.Policies[0].LastEvaluatedAt == nil || !got.Policies[0].LastEvaluatedAt.Equal(runStart) {
		t.Errorf("LastEvaluatedAt = %v; want run start %v", got.Policies[0].LastEvaluatedAt, runStart)
	}
	if got.Policies[0].IsCarriedForward {
		t.Error("IsCarriedForward should be false for a fresh pass")
	}
}

// A carried-forward result with a nil CarryForward ref must not panic;
// LastEvaluatedAt falls through to the run start.
func TestBuild_CarriedForward_NilRefDoesNotPanic(t *testing.T) {
	runStart := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	results := []core.PolicyResult{{PolicyID: "p1", Status: core.StatusCarriedForward}}
	got := Build(results, &Environment{StartedAt: runStart})
	if !got.Policies[0].IsCarriedForward {
		t.Error("IsCarriedForward = false; want true")
	}
	if got.Policies[0].LastEvaluatedAt == nil || !got.Policies[0].LastEvaluatedAt.Equal(runStart) {
		t.Errorf("LastEvaluatedAt = %v; want run start (nil ref fallback)", got.Policies[0].LastEvaluatedAt)
	}
}

// Build with a nil Environment must not panic and produces an empty
// (zero-value) environment.
func TestBuild_NilEnvironment(t *testing.T) {
	got := Build([]core.PolicyResult{{PolicyID: "p1", Status: core.StatusPass}}, nil)
	if got.Schema != SchemaVersion {
		t.Errorf("Schema = %q; want %q", got.Schema, SchemaVersion)
	}
	if len(got.Policies) != 1 {
		t.Errorf("Policies = %d; want 1", len(got.Policies))
	}
}

// Per-policy cadence scalars and the multi-framework controls list are
// carried through to the aggregated policy (and remain non-identifying).
func TestBuild_CadenceScalarsAndControlsPassThrough(t *testing.T) {
	nextDue := time.Date(2026, 5, 25, 9, 0, 0, 0, time.UTC)
	results := []core.PolicyResult{{
		PolicyID: "p1",
		Status:   core.StatusPass,
		Controls: []core.ControlRef{
			{Framework: "soc2", ControlID: "SOC2.CC6.1"},
			{Framework: "iso27001", ControlID: "A.9.4.2"},
		},
		ConfiguredCadence: "daily",
		NextDueAt:         nextDue,
		PolicyContentHash: "sha256:abc",
	}}
	got := Build(results, &Environment{StartedAt: time.Now()})
	ap := got.Policies[0]
	if ap.ConfiguredCadence != "daily" {
		t.Errorf("ConfiguredCadence = %q", ap.ConfiguredCadence)
	}
	if ap.NextDueAt == nil || !ap.NextDueAt.Equal(nextDue) {
		t.Errorf("NextDueAt = %v; want %v", ap.NextDueAt, nextDue)
	}
	if ap.PolicyContentHash != "sha256:abc" {
		t.Errorf("PolicyContentHash = %q", ap.PolicyContentHash)
	}
	if len(ap.Controls) != 2 {
		t.Fatalf("Controls = %d; want 2", len(ap.Controls))
	}
	if ap.Controls[1].Framework != "iso27001" {
		t.Errorf("Controls[1].Framework = %q; want iso27001", ap.Controls[1].Framework)
	}
}
