package planner

import (
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// testPolicyIDMFAAdmins is the policy every cadence-decision fixture in
// this file reads state for.
const testPolicyIDMFAAdmins = "soc2.cc6.1.mfa_enforced_admins"

// TestDecideEvaluation_EmptyHashForcesEvaluate pins the fail-closed
// direction of the content-hash gate.
//
// core.PolicyContentHash returns "" when it cannot canonicalize a
// policy. The gate used to read `contentHash != "" && ...`, which
// skipped the mismatch branch entirely on an empty hash and dropped
// through to the cadence check — so an uncanonicalizable policy that
// had passed recently carried its old signed envelope forward. That is
// fail-OPEN on exactly the input we understand least. An unknown hash
// must mean "evaluate".
func TestDecideEvaluation_EmptyHashForcesEvaluate(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	prior := &core.PolicyState{
		PolicyID: testPolicyIDMFAAdmins,
		// Recent pass under a daily cadence: the cadence gate alone
		// would carry this forward.
		LastRunAt:      now.Add(-1 * time.Hour),
		LastPassAt:     now.Add(-1 * time.Hour),
		LastRunStatus:  core.StatusPass,
		LastPolicyHash: "sha256:known-prior-hash",
	}

	should, reason := decideEvaluation(&Filter{}, "daily", "", prior, now)
	if !should {
		t.Fatalf("ShouldEvaluate = false; want true (empty content hash must force evaluation, not carry forward)")
	}
	if reason == "" {
		t.Errorf("expected a reason explaining the forced evaluation")
	}
}

// An empty hash forces evaluation even when the prior state recorded no
// hash of its own — neither side being known is strictly less evidence
// of sameness, not more.
func TestDecideEvaluation_EmptyHashWithNoPriorHashForcesEvaluate(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	prior := &core.PolicyState{
		PolicyID:      testPolicyIDMFAAdmins,
		LastRunAt:     now.Add(-1 * time.Hour),
		LastPassAt:    now.Add(-1 * time.Hour),
		LastRunStatus: core.StatusPass,
	}

	if should, _ := decideEvaluation(&Filter{}, "daily", "", prior, now); !should {
		t.Errorf("ShouldEvaluate = false; want true (empty hash on both sides must still evaluate)")
	}
}

// A known hash matching the prior state still carries forward — the
// fail-closed rule above must not have collapsed the gate into
// "always evaluate".
func TestDecideEvaluation_MatchingHashStillCarriesForward(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	const hash = "sha256:same"
	prior := &core.PolicyState{
		PolicyID:       testPolicyIDMFAAdmins,
		LastRunAt:      now.Add(-1 * time.Hour),
		LastPassAt:     now.Add(-1 * time.Hour),
		LastRunStatus:  core.StatusPass,
		LastPolicyHash: hash,
	}

	should, reason := decideEvaluation(&Filter{}, "daily", hash, prior, now)
	if should {
		t.Errorf("ShouldEvaluate = true; want false (hash unchanged, daily cadence not elapsed)")
	}
	if reason == "" {
		t.Errorf("a carry-forward must record why")
	}
}
