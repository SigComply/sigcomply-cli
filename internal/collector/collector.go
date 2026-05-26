// Package collector is L4 of the SigComply CLI. For each planned
// policy it invokes the bound source plugins, validates the records
// (schema validation is deferred to a future milestone — see post-M6
// work plan), signs one envelope per (slot, source) pair, and writes
// the envelope to the vault. Per the KISS-no-DRY axiom, there is no
// record cache spanning policies: N policies → N invocations of
// Collect even if the same (plugin, slot) recurs.
//
// See docs/architecture/02-layers.md §L4 and 04-source-plugins.md.
package collector

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
)

// EnvelopeFormatVersion is stamped on every envelope produced by the
// collector. Mirrors what auditors and the SPA verifier key against.
const EnvelopeFormatVersion = "envelope.v1"

// Input carries everything the collector needs.
type Input struct {
	Plan *planner.RunPlan
	// Sources is the populated source-plugin registry.
	Sources *registry.Registry[core.SourcePlugin]
	// EvidenceTypes is the registered evidence-type catalog. The
	// collector validates every emitted record's payload against its
	// type's schema before signing — a schema mismatch is treated as a
	// collection error and tagged on the policy. When nil (legacy
	// callers, tests that don't exercise validation), validation is
	// skipped.
	EvidenceTypes *registry.Registry[core.EvidenceType]
	// Vault is where envelopes land.
	Vault core.Vault
	// RunRoot is the framework-prefixed root inside the vault for this
	// run, e.g. "soc2/2026-Q1/run_20260215T140000Z_a3f8b2c1".
	RunRoot string
	// SlotParamsExtras is appended to each binding's SlotParams before
	// invoking Collect. The orchestrator uses this to inject period_id,
	// period_start, period_end, now — values the planner knows but the
	// project config does not.
	SlotParamsExtras map[string]any
	// Now is the run's reference time for envelope ProducedAt.
	Now time.Time
	// RetryPolicy controls per-slot retry behavior. Zero value (or
	// MaxAttempts <= 1) is the legacy no-retry behavior. The
	// orchestrator selects a mode-appropriate policy (PR=generous,
	// Scheduled=fast-fail, Manual=none) and threads it through here.
	RetryPolicy RetryPolicy
}

// Output is what L5 (evaluator) consumes.
type Output struct {
	// RecordsByPolicy[policyID][slotName] holds the union of all bound
	// sources' records for that slot.
	RecordsByPolicy map[string]map[string][]core.EvidenceRecord
	// EnvelopesByPolicy[policyID] holds the relative vault paths of the
	// envelopes written for that policy. Used by the evaluator to
	// populate PolicyResult.EvidenceEnvelopes.
	EnvelopesByPolicy map[string][]string
	// CollectErrorsByPolicy[policyID] is set when at least one bound
	// source returned an error. The evaluator turns this into a
	// status=error result.
	CollectErrorsByPolicy map[string]error
}

// Collect runs L4 for the entire plan.
func Collect(ctx context.Context, in *Input) (*Output, error) {
	if in == nil || in.Plan == nil {
		return nil, fmt.Errorf("collector: nil Input or Plan")
	}
	if in.Sources == nil {
		return nil, fmt.Errorf("collector: nil source registry")
	}
	if in.Vault == nil {
		return nil, fmt.Errorf("collector: nil vault")
	}
	out := &Output{
		RecordsByPolicy:       make(map[string]map[string][]core.EvidenceRecord, len(in.Plan.Policies)),
		EnvelopesByPolicy:     make(map[string][]string, len(in.Plan.Policies)),
		CollectErrorsByPolicy: make(map[string]error),
	}
	for i := range in.Plan.Policies {
		pp := &in.Plan.Policies[i]
		if !pp.ShouldEvaluate {
			// Carry-forward: the planner decided this policy's prior
			// evaluation is still valid for this period. No fresh
			// evidence is collected and no envelope is written; the
			// evaluator emits a carry-forward result referencing the
			// prior envelope. See docs/architecture/11-cadence-model.md.
			continue
		}
		if pp.Exception != nil && pp.Exception.ResourceID == "" && pp.Exception.ResourcePattern == "" {
			// Whole-policy exception — no need to collect.
			continue
		}
		if err := collectPolicy(ctx, pp, in, out); err != nil {
			out.CollectErrorsByPolicy[pp.Spec.ID] = err
		}
	}
	return out, nil
}

func collectPolicy(ctx context.Context, pp *planner.PlannedPolicy, in *Input, out *Output) error {
	slotMap := make(map[string][]core.EvidenceRecord, len(pp.Bindings))
	var firstErr error
	for _, slotName := range sortedKeys(pp.Bindings) {
		bindings := pp.Bindings[slotName]
		for i := range bindings {
			b := &bindings[i]
			records, err := collectBinding(ctx, pp, slotName, b, in, out)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			if records != nil {
				slotMap[slotName] = append(slotMap[slotName], records...)
			}
		}
	}
	out.RecordsByPolicy[pp.Spec.ID] = slotMap
	return firstErr
}

// collectBinding runs one (policy, slot, source) binding end-to-end:
// look up the plugin, call Collect, validate against schema, type-
// check, sort, group by type, sign, persist. Returns the records that
// landed in the vault on success; on failure returns nil and a
// fully-formed error that the caller threads into firstErr.
func collectBinding(ctx context.Context, pp *planner.PlannedPolicy, slotName string, b *planner.Binding, in *Input, out *Output) ([]core.EvidenceRecord, error) {
	plugin, ok := in.Sources.Lookup(b.SourceID)
	if !ok {
		return nil, fmt.Errorf("collector: source %q not registered for policy %q", b.SourceID, pp.Spec.ID)
	}
	req := buildSlotRequest(pp, slotName, b, in.SlotParamsExtras)
	var records []core.EvidenceRecord
	if err := withRetry(ctx, in.RetryPolicy, func() error {
		var inner error
		records, inner = plugin.Collect(ctx, req)
		return inner
	}); err != nil {
		return nil, fmt.Errorf("collector: policy %q slot %q source %q: %w", pp.Spec.ID, slotName, b.SourceID, err)
	}
	if err := validateRecords(in.EvidenceTypes, records); err != nil {
		return nil, fmt.Errorf("collector: policy %q slot %q source %q: schema validation: %w", pp.Spec.ID, slotName, b.SourceID, err)
	}
	if err := checkAcceptedTypes(records, b.AcceptedTypes); err != nil {
		return nil, fmt.Errorf("collector: policy %q slot %q source %q: %w", pp.Spec.ID, slotName, b.SourceID, err)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })

	// Group records by Type so each envelope file holds records of
	// one type — keeps the envelope filename expressive
	// (`{type}__{source}.json`) and lets an auditor verify per-type.
	// A source that emits a single type produces one envelope; a
	// source emitting multiple types satisfying the slot produces
	// one envelope per type.
	for _, group := range groupByType(records, b.AcceptedTypes) {
		if err := writeEnvelope(ctx, in, pp, slotName, b, group, out); err != nil {
			return records, err
		}
	}
	return records, nil
}

func writeEnvelope(ctx context.Context, in *Input, pp *planner.PlannedPolicy, slotName string, b *planner.Binding, group typeGroup, out *Output) error {
	env := &core.Envelope{
		FormatVersion: EnvelopeFormatVersion,
		ProducedAt:    in.Now,
		Records:       group.records,
	}
	if err := sign.Envelope(env); err != nil {
		return fmt.Errorf("collector: sign envelope for %q/%s/%s/%s: %w", pp.Spec.ID, slotName, b.SourceID, group.evidenceType, err)
	}
	path := envelopePath(in.RunRoot, pp.Spec.ID, group.evidenceType, b.SourceID, b.CatalogID)
	if err := in.Vault.PutEnvelope(ctx, path, env); err != nil {
		return fmt.Errorf("collector: write envelope %s: %w", path, err)
	}
	out.EnvelopesByPolicy[pp.Spec.ID] = append(out.EnvelopesByPolicy[pp.Spec.ID], path)
	return nil
}

func buildSlotRequest(pp *planner.PlannedPolicy, slotName string, b *planner.Binding, extras map[string]any) core.SlotRequest {
	params := make(map[string]any, len(b.SlotParams)+len(extras)+1)
	for k, v := range extras {
		params[k] = v
	}
	for k, v := range b.SlotParams {
		params[k] = v
	}
	if b.CatalogID != "" {
		params["catalog_id"] = b.CatalogID
	}
	return core.SlotRequest{
		PolicyID:      pp.Spec.ID,
		AcceptedTypes: append([]string(nil), b.AcceptedTypes...),
		SlotName:      slotName,
		Params:        params,
	}
}

type typeGroup struct {
	evidenceType string
	records      []core.EvidenceRecord
}

// groupByType buckets records by their Type, preserving the slot's
// AcceptedTypes order so envelope file ordering across runs stays
// stable. A record whose Type is not in acceptedTypes is rejected
// upstream by checkAcceptedTypes; groupByType silently skips it as a
// defense-in-depth measure.
func groupByType(records []core.EvidenceRecord, acceptedTypes []string) []typeGroup {
	accept := make(map[string]struct{}, len(acceptedTypes))
	for _, t := range acceptedTypes {
		accept[t] = struct{}{}
	}
	buckets := make(map[string][]core.EvidenceRecord, len(acceptedTypes))
	for i := range records {
		r := records[i]
		if _, ok := accept[r.Type]; !ok {
			continue
		}
		buckets[r.Type] = append(buckets[r.Type], r)
	}
	out := make([]typeGroup, 0, len(buckets))
	for _, t := range acceptedTypes {
		if rs, ok := buckets[t]; ok {
			out = append(out, typeGroup{evidenceType: t, records: rs})
		}
	}
	return out
}

// checkAcceptedTypes verifies every record's Type appears in the
// binding's AcceptedTypes set. A plugin returning a record whose Type
// is outside the negotiated set is a contract violation surfaced as a
// collection error (exit code 3 via the policy error tag).
func checkAcceptedTypes(records []core.EvidenceRecord, acceptedTypes []string) error {
	if len(records) == 0 {
		return nil
	}
	accept := make(map[string]struct{}, len(acceptedTypes))
	for _, t := range acceptedTypes {
		accept[t] = struct{}{}
	}
	for i := range records {
		if _, ok := accept[records[i].Type]; !ok {
			return fmt.Errorf("record %q has type %q which is outside the binding's AcceptedTypes %v", records[i].ID, records[i].Type, acceptedTypes)
		}
	}
	return nil
}

func envelopePath(runRoot, policyID, evidenceType, sourceID, catalogID string) string {
	suffix := sourceID
	if catalogID != "" {
		suffix = sourceID + "_" + catalogID
	}
	return fmt.Sprintf("%s/policies/%s/envelopes/%s__%s.json", runRoot, policyID, evidenceType, suffix)
}

// validateRecords checks every record's payload against the schema
// registered for its declared Type. Records whose Type has no
// registered schema are accepted unchanged — this is the migration
// path: schemas can be added incrementally without forcing every
// type to be authored up-front. A nil EvidenceTypes registry skips
// validation entirely (used by tests that don't exercise schemas).
//
// Returning the first failure (rather than a list) keeps callers
// simple: the collector tags the policy with status=error on the
// first bad record and continues to the next binding. A run with
// many schema violations surfaces them one bad-record-per-rerun.
func validateRecords(types *registry.Registry[core.EvidenceType], records []core.EvidenceRecord) error {
	if types == nil {
		return nil
	}
	for i := range records {
		r := &records[i]
		et, ok := types.Lookup(r.Type)
		if !ok {
			continue
		}
		if err := evidencetypes.Validate(et.Schema, r.Payload); err != nil {
			return fmt.Errorf("record %q (type %q): %w", r.ID, r.Type, err)
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
