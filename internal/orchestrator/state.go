package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// stateBulkReadConcurrency is the worker-pool size used by
// BulkReadPolicyStates to fan out per-shard GETs against the vault.
// 8 workers balances S3 round-trip latency (~50ms) against an HTTPS
// connection-pool size that every supported backend handles
// comfortably.
const stateBulkReadConcurrency = 8

// PolicyStatePath returns the canonical vault path for a single
// policy's state shard. State shards live OUTSIDE the per-period
// evidence prefix because they are mutable scheduling state — never
// signed, never an audit deliverable. See docs/architecture/05-
// vault-layout.md §State.
//
// Path scheme: state/{framework}/policies/{policy_id}.json
func PolicyStatePath(framework, policyID string) string {
	return fmt.Sprintf("state/%s/policies/%s.json", framework, policyID)
}

// PolicyStatePrefix returns the directory prefix that holds every
// state shard for a framework. Useful for List operations.
func PolicyStatePrefix(framework string) string {
	return fmt.Sprintf("state/%s/policies/", framework)
}

// errCorruptShard marks a shard that was read but could not be parsed,
// or whose timestamps cannot be true (futureDated).
var errCorruptShard = errors.New("corrupt state shard")

// stateClockSkew is how far a shard's timestamps may lie ahead of the
// run clock: runners' clocks differ by seconds, so a shard written by
// one slightly ahead is honest. Anything later is corrupt.
const stateClockSkew = 5 * time.Minute

// futureDated reports the first of the shard's "when did this happen"
// timestamps that is later than now plus stateClockSkew. State shards
// are unsigned scheduling hints, so a shard planted with a pass dated
// next year would carry an unevaluated pass forward, and one with a
// future last_run_at would make the monotonic write guard refuse every
// honest write. NextDueAt is a future time by design and is not checked.
func futureDated(s *core.PolicyState, now time.Time) (field string, at time.Time, ok bool) {
	limit := now.Add(stateClockSkew)
	for _, f := range []struct {
		name string
		at   time.Time
	}{
		{"last_run_at", s.LastRunAt},
		{"last_pass_at", s.LastPassAt},
		{"last_fail_at", s.LastFailAt},
	} {
		if f.at.After(limit) {
			return f.name, f.at, true
		}
	}
	return "", time.Time{}, false
}

// ReadPolicyState fetches one state shard from the vault. A missing
// shard returns (nil, nil) — the planner treats this as "first run"
// and evaluates the policy unconditionally. A corrupted shard
// returns an error so the caller can log-and-degrade explicitly;
// silently discarding state would mask a real problem (lost run
// history, bucket misconfiguration).
func ReadPolicyState(ctx context.Context, vault core.Vault, framework, policyID string) (*core.PolicyState, error) {
	if vault == nil {
		return nil, fmt.Errorf("policy-state: nil vault")
	}
	if framework == "" || policyID == "" {
		return nil, fmt.Errorf("policy-state: empty framework or policy_id")
	}
	body, err := vault.GetBinary(ctx, PolicyStatePath(framework, policyID))
	if err != nil {
		if isVaultNotFound(err) {
			return nil, nil //nolint:nilnil // missing shard is "first run", a real case
		}
		return nil, fmt.Errorf("policy-state: read %s: %w", policyID, err)
	}
	var s core.PolicyState
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("policy-state: parse %s: %w: %w", policyID, errCorruptShard, err)
	}
	if s.PolicyID == "" {
		s.PolicyID = policyID
	}
	if s.Framework == "" {
		s.Framework = framework
	}
	return &s, nil
}

// WritePolicyState persists one state shard with a monotonic guard:
// the write is accepted iff the new state's LastRunAt is strictly
// newer than the persisted shard's LastRunAt, OR the two are equal
// and the new LastRunID sorts lexicographically higher. This
// prevents an out-of-order CI run (slow clock, late-arriving worker)
// from clobbering a more-recent successor.
//
// The function performs a read-then-write — a true concurrent
// collision is rare in CI (most orgs serialize runs against one
// vault) and the surviving writer wins deterministically. On
// backends that expose conditional writes (S3 If-Match, GCS
// generation preconditions, Azure ETag) a future revision can
// wire those in through the core.Vault interface.
//
// A missing shard is treated as "no prior state" — the new state
// wins, and so is a corrupt one, including one dated after now plus
// stateClockSkew (futureDated). Returns nil when the write is accepted, nil when it is
// rejected by the monotonic guard (the caller's perspective: "the
// vault already has equivalent-or-newer state, which is fine"), and
// a non-nil error only for true I/O failures.
func WritePolicyState(ctx context.Context, vault core.Vault, ps *core.PolicyState, now time.Time) error {
	if vault == nil {
		return fmt.Errorf("policy-state: nil vault")
	}
	if ps == nil {
		return fmt.Errorf("policy-state: nil state")
	}
	if ps.PolicyID == "" || ps.Framework == "" {
		return fmt.Errorf("policy-state: empty PolicyID or Framework")
	}
	if ps.SchemaVersion == "" {
		ps.SchemaVersion = core.PolicyStateSchemaVersion
	}
	existing, err := ReadPolicyState(ctx, vault, ps.Framework, ps.PolicyID)
	if existing != nil {
		if _, _, future := futureDated(existing, now); future {
			err = errCorruptShard
		}
	}
	switch {
	case errors.Is(err, errCorruptShard):
		// The shard is loss-tolerant (Invariant 5): an unparseable one is
		// replaced, or every later run would warn and never record state
		// for this policy. A plain read failure is different and still
		// stops the write, since the guard could not see what is there.
		existing = nil
	case err != nil:
		return err
	}
	if !shouldAcceptWrite(existing, ps) {
		return nil
	}
	return vault.PutJSON(ctx, PolicyStatePath(ps.Framework, ps.PolicyID), ps)
}

// shouldAcceptWrite implements the monotonic write rule. Exported
// from the package only via WritePolicyState; kept unexported so the
// guard logic stays single-sourced.
func shouldAcceptWrite(existing, incoming *core.PolicyState) bool {
	if existing == nil {
		return true
	}
	if incoming.LastRunAt.After(existing.LastRunAt) {
		return true
	}
	if incoming.LastRunAt.Equal(existing.LastRunAt) {
		// Tiebreaker: run_id lexicographic. UUIDs are random so this
		// is effectively a coin flip, but it IS deterministic: every
		// observer agrees on the winner.
		return incoming.LastRunID > existing.LastRunID
	}
	return false
}

// BulkReadPolicyStates fetches state shards for many policies in
// parallel and returns a map keyed by policy ID. Missing shards are
// represented as a nil value (not absent from the map) so callers
// can distinguish "policy in framework but never run" from "policy
// not in this framework at all."
//
// Parallelism is bounded by stateBulkReadConcurrency. Errors from
// individual shards are collected; a partial failure does NOT abort
// the overall load — the orchestrator degrades gracefully by
// treating an unreadable shard as a first run (with a warning
// emitted via the logger).
func BulkReadPolicyStates(ctx context.Context, vault core.Vault, framework string, policyIDs []string) (map[string]*core.PolicyState, []error) {
	out := make(map[string]*core.PolicyState, len(policyIDs))
	for _, id := range policyIDs {
		out[id] = nil
	}
	if len(policyIDs) == 0 {
		return out, nil
	}
	var mu sync.Mutex
	errs := make([]error, 0)
	sem := make(chan struct{}, stateBulkReadConcurrency)
	var wg sync.WaitGroup
	for _, id := range policyIDs {
		id := id
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ps, err := ReadPolicyState(ctx, vault, framework, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("policy %s: %w", id, err))
				return
			}
			out[id] = ps
		}()
	}
	wg.Wait()
	return out, errs
}

// ListPolicyStates enumerates every state shard under a framework's
// prefix, for orphan-shard detection (state for a policy no longer in
// the bundle). Earlier drafts of this comment also named `sigcomply
// status` and `sigcomply audit-ledger`; neither command exists.
//
// The vault's List backend is authoritative for the result. An
// unimplemented List (some test vaults) returns an empty map — that
// is the correct degradation for "no state to enumerate."
func ListPolicyStates(ctx context.Context, vault core.Vault, framework string) (map[string]*core.PolicyState, error) {
	if vault == nil {
		return nil, fmt.Errorf("policy-state: nil vault")
	}
	prefix := PolicyStatePrefix(framework)
	keys, err := vault.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("policy-state: list %s: %w", prefix, err)
	}
	out := make(map[string]*core.PolicyState, len(keys))
	for _, key := range keys {
		policyID := policyIDFromStatePath(prefix, key)
		if policyID == "" {
			continue
		}
		ps, err := ReadPolicyState(ctx, vault, framework, policyID)
		if err != nil {
			return out, fmt.Errorf("policy-state: bulk read %s: %w", policyID, err)
		}
		out[policyID] = ps
	}
	return out, nil
}

// policyIDFromStatePath strips the prefix and the .json suffix from a
// vault-returned key. Returns "" when the key doesn't conform — the
// caller skips non-shard entries silently.
func policyIDFromStatePath(prefix, key string) string {
	if !strings.HasPrefix(key, prefix) {
		return ""
	}
	base := strings.TrimPrefix(key, prefix)
	if !strings.HasSuffix(base, ".json") {
		return ""
	}
	return strings.TrimSuffix(base, ".json")
}

// AdvancePolicyState updates the per-policy state at the end of a
// run that actually evaluated the policy. The caller passes the
// policy result, the run's start timestamp, run ID, period ID,
// content hash, and envelope reference; this helper produces the
// new PolicyState value (without writing it). The orchestrator's
// AdvanceAllPolicyStates writes it via WritePolicyState.
//
// For carry-forward results (where the run did NOT evaluate the
// policy) the orchestrator skips this function entirely — the
// existing state shard is preserved verbatim.
func AdvancePolicyState(
	framework, policyID, runID, periodID, configuredCadence, policyHash, envelopeRef string,
	status core.PolicyStatus,
	startedAt time.Time,
	cadenceInterval time.Duration,
) *core.PolicyState {
	ps := &core.PolicyState{
		SchemaVersion:     core.PolicyStateSchemaVersion,
		PolicyID:          policyID,
		Framework:         framework,
		LastRunAt:         startedAt.UTC(),
		LastRunStatus:     status,
		LastPeriodID:      periodID,
		LastRunID:         runID,
		LastPolicyHash:    policyHash,
		LastEnvelopeRef:   envelopeRef,
		ConfiguredCadence: configuredCadence,
	}
	switch status {
	case core.StatusPass:
		ps.LastPassAt = startedAt.UTC()
	case core.StatusFail, core.StatusError:
		ps.LastFailAt = startedAt.UTC()
	default:
		// skip / na / waived: no pass-vs-fail signal to record; the
		// status itself drives the next planner pass via the
		// on_fail_retry branch (any non-pass terminal status forces
		// re-evaluation).
	}
	if !ps.LastPassAt.IsZero() && cadenceInterval > 0 {
		ps.NextDueAt = ps.LastPassAt.Add(cadenceInterval).UTC()
	}
	return ps
}

// isVaultNotFound matches the "not found" convention used by every
// in-tree vault backend: local, s3, gcs, azureblob all wrap their
// backend-specific 404 in `fmt.Errorf("... vault: not found: ...")`.
// Substring-match on "not found" keeps this single helper backend-
// agnostic without per-backend dispatch.
func isVaultNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found")
}

// joinVaultPath is a thin alias for path.Join, exported here to keep
// callers from importing both stdlib path and this package's
// path-shaping helpers. Used by orchestrator code that composes
// state prefixes with policy IDs at runtime.
func joinVaultPath(parts ...string) string {
	return path.Join(parts...)
}

// ensure path.Join stays linked even when no caller uses
// joinVaultPath yet (keeps `go vet` quiet during phased rollout).
var _ = joinVaultPath
