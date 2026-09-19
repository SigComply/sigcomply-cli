package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// PolicyStateSchemaVersion is the schema stamp on the per-policy
// state shard. Bumped on any wire-format change.
const PolicyStateSchemaVersion = "policy-state.v1"

// PolicyState is the per-policy operational record kept in the vault
// at state/{framework}/policies/{policy_id}.json. It is mutable
// scheduling state — never part of any signed manifest, never an
// audit deliverable, never trusted by an auditor (signed envelopes
// are the trust anchor).
//
// The state's only consumer is the planner, which uses it to decide
// whether a policy is due to evaluate in the current run. Loss of a
// state shard is recoverable: the planner treats a missing shard as
// "first run" and evaluates the policy. The shard is rewritten after
// every evaluation.
//
// See docs/architecture/10-cadence-model.md for the model.
type PolicyState struct {
	SchemaVersion string `json:"schema_version"`

	PolicyID  string `json:"policy_id"`
	Framework string `json:"framework"`

	// LastRunAt is the run-start timestamp of the most recent run that
	// evaluated this policy (pass, fail, error, or skipped-with-fresh-
	// data). Carried-forward runs do NOT update LastRunAt — by
	// definition they did not evaluate.
	LastRunAt time.Time `json:"last_run_at"`

	// LastPassAt is the run-start timestamp of the most recent run that
	// evaluated this policy and produced StatusPass. Cadence gating
	// uses this field, not LastRunAt — so a failed policy is "due"
	// again on the next run regardless of nominal cadence (the
	// on_fail_retry rule).
	LastPassAt time.Time `json:"last_pass_at,omitempty"`

	// LastFailAt is the run-start timestamp of the most recent run that
	// evaluated this policy and produced StatusFail.
	LastFailAt time.Time `json:"last_fail_at,omitempty"`

	// LastRunStatus is the terminal status of the most recent
	// evaluation. One of: pass, fail, error, skip, na, waived. Empty
	// when this is a freshly-allocated state with no run history.
	LastRunStatus PolicyStatus `json:"last_run_status,omitempty"`

	// LastPeriodID is the period_id that the most recent evaluation
	// belongs to. Carry-forward results reference this period via the
	// envelope under LastEnvelopeRef.
	LastPeriodID string `json:"last_period_id,omitempty"`

	// LastRunID is the run_id of the most recent evaluation. The
	// concurrent-write rule uses it as a tiebreaker when two runs
	// share LastRunAt to the second.
	LastRunID string `json:"last_run_id,omitempty"`

	// LastPolicyHash is the SHA-256 of the canonicalized policy spec
	// at the time of the most recent evaluation. A bundle update that
	// changes the policy text invalidates this hash, marking the
	// policy due on the next run regardless of cadence. The actual
	// hash for the current run is computed at plan time via
	// PolicyContentHash.
	LastPolicyHash string `json:"last_policy_hash,omitempty"`

	// LastEnvelopeRef is the run-relative path of the signed evidence
	// envelope produced by the most recent evaluation. Carry-forward
	// results emit a reference to this path so an auditor can
	// hash-verify the original envelope independently.
	LastEnvelopeRef string `json:"last_envelope_ref,omitempty"`

	// NextDueAt is the wall-clock time after which the policy is
	// considered due again under its configured cadence. Pre-computed
	// at end of each run so the next planner pass is a single field
	// read per policy. For "continuous" / "every: 0s" cadences this
	// is the zero time (always due).
	NextDueAt time.Time `json:"next_due_at,omitempty"`

	// ConfiguredCadence is the cadence string in effect at the most
	// recent evaluation ("daily", "every: 6h", etc.). Captured so a
	// subsequent run can detect a configuration change and re-
	// evaluate even when the time-since-last-pass would suggest
	// otherwise. Currently informational; the planner gates on
	// LastPolicyHash for content changes.
	ConfiguredCadence string `json:"configured_cadence,omitempty"`
}

// IsFirstRun reports whether this policy has never been evaluated.
// The planner uses this to emit the first-run warning and to mark a
// policy as immediately due regardless of cadence.
func (p *PolicyState) IsFirstRun() bool {
	return p == nil || p.LastRunAt.IsZero()
}

// PolicyContentHash computes the SHA-256 of a canonicalized policy
// spec plus its referenced evidence-type schema digests. A change to
// any of the hashed fields — the policy's ID, primary control, rule
// reference, **pass_when body** (every clause, quantifier, filter,
// operator, field, value and threshold, in order), severity, cadence,
// on_push flag, slot definitions or parameters — or to any referenced
// schema produces a different hash; the planner treats hash mismatch
// with PolicyState.LastPolicyHash as "due regardless of cadence" so a
// bundle update can never silently re-certify old evidence with new
// rules.
//
// pass_when is load-bearing here, not incidental: every shipped policy
// is pass_when-driven and none uses the rule: escape hatch, so a hash
// that omitted it would be blind to essentially every real policy edit.
//
// schemaDigests is a map keyed by evidence-type ID; values are the
// digests of the corresponding JSON Schema as registered. An empty
// map is acceptable (callers without schema-digest access pass nil)
// — the hash will still discriminate policy-spec changes, just not
// schema bumps.
//
// Returns "" for a nil policy, and for the one case a real policy can
// fail to marshal: a pass_when Value holding something encoding/json
// cannot represent. An empty hash is not a "no change" signal — the
// planner must (and does) treat it as "evaluate".
func PolicyContentHash(p *Policy, schemaDigests map[string]string) string {
	if p == nil {
		return ""
	}
	canon := canonicalizePolicy(p, schemaDigests)
	body, err := json.Marshal(canon)
	if err != nil {
		// Reachable only through a pass_when Value that encoding/json
		// cannot represent (the rest of the projection is hand-built
		// from strings and bools). Return the empty hash; the planner
		// forces evaluation on it rather than comparing.
		return ""
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalizePolicy projects a Policy plus its schema digests into a
// stable shape for hashing. Maps are flattened to sorted (key, value)
// slices so JSON marshaling is deterministic across runs.
func canonicalizePolicy(p *Policy, schemaDigests map[string]string) any {
	type kv struct {
		K string `json:"k"`
		V any    `json:"v"`
	}
	sortedSlots := make([]kv, 0, len(p.Slots))
	for name, s := range p.Slots {
		accepts := append([]string(nil), s.Accepts...)
		sort.Strings(accepts)
		slot := map[string]any{
			"accepts":     accepts,
			"cardinality": string(s.Cardinality),
			"required":    s.Required,
		}
		if s.Role != SlotRoleNone {
			// Only when set, so existing policies keep their hash.
			slot["role"] = string(s.Role)
		}
		sortedSlots = append(sortedSlots, kv{K: name, V: slot})
	}
	sort.Slice(sortedSlots, func(i, j int) bool { return sortedSlots[i].K < sortedSlots[j].K })

	sortedParams := make([]kv, 0, len(p.Parameters))
	for name, ps := range p.Parameters {
		sortedParams = append(sortedParams, kv{K: name, V: map[string]any{
			"type":    ps.Type,
			"default": ps.Default,
		}})
	}
	sort.Slice(sortedParams, func(i, j int) bool { return sortedParams[i].K < sortedParams[j].K })

	sortedSchemas := make([]kv, 0, len(schemaDigests))
	for id, digest := range schemaDigests {
		sortedSchemas = append(sortedSchemas, kv{K: id, V: digest})
	}
	sort.Slice(sortedSchemas, func(i, j int) bool { return sortedSchemas[i].K < sortedSchemas[j].K })

	return map[string]any{
		"id":         p.ID,
		"control":    PrimaryControlID(p.Controls),
		"rule":       p.RuleRef,
		"pass_when":  canonicalizePassWhen(p.PassWhen),
		"severity":   string(p.Severity),
		"cadence":    p.Cadence,
		"on_push":    p.OnPush,
		"slots":      sortedSlots,
		"parameters": sortedParams,
		"schemas":    sortedSchemas,
	}
}

// canonicalizePassWhen projects a PassWhenSpec into a stable shape for
// hashing. Nil spec → nil (marshaled as JSON null), so every policy's
// projection carries the key whether or not it has a pass_when block.
//
// The projection is built by hand rather than marshaling PassWhenSpec
// directly because none of the pass_when types carry `json:` tags:
// encoding/json would key on Go field names, silently rotating every
// policy's hash on a field rename that changes no behavior. The literal
// key names below are the wire contract; rename a Go field freely, these
// stay put.
//
// Clause order and sub-condition order are semantic (they decide which
// slot is evaluated first and how a compound short-circuits), so lists
// are never sorted.
func canonicalizePassWhen(pw *PassWhenSpec) any {
	if pw == nil {
		return nil
	}
	clauses := make([]any, 0, len(pw.Clauses))
	for i := range pw.Clauses {
		c := &pw.Clauses[i]
		// MinPercentage is emitted as a key always — null when unset —
		// so "threshold removed" cannot canonicalize to the same bytes
		// as "threshold absent from the start".
		var minPct any
		if c.MinPercentage != nil {
			minPct = *c.MinPercentage
		}
		clauses = append(clauses, map[string]any{
			"slot":           c.Slot,
			"quantifier":     string(c.Quantifier),
			"condition":      canonicalizeCondition(c.Condition),
			"filter":         canonicalizeCondition(c.Filter),
			"violation_msg":  c.ViolationMsg,
			"identity_key":   c.IdentityKey,
			"min_percentage": minPct,
		})
	}
	return map[string]any{"clauses": clauses}
}

// canonicalizeCondition projects one pass_when condition (and, through
// Conditions / Where, the whole expression tree below it). Value is an
// untyped `any` fed by Go policy builders and by gopkg.in/yaml.v3 —
// scalars, []any and map[string]any — all of which encoding/json
// renders deterministically (object keys are sorted on marshal). It is
// carried through as-is: the hash must discriminate a threshold change
// from a threshold typo, and only the value itself can do that.
func canonicalizeCondition(c *PassWhenCondition) any {
	if c == nil {
		return nil
	}
	var subs any
	if c.Conditions != nil {
		list := make([]any, 0, len(c.Conditions))
		for _, sub := range c.Conditions {
			list = append(list, canonicalizeCondition(sub))
		}
		subs = list
	}
	return map[string]any{
		"op":           c.Op,
		"field":        c.Field,
		"value":        c.Value,
		"conditions":   subs,
		"in_slot":      c.InSlot,
		"remote_field": c.RemoteField,
		"normalize":    c.Normalize,
		"where":        canonicalizeCondition(c.Where),
	}
}
