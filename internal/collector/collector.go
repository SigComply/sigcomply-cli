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
		slot := pp.Spec.Slots[slotName]
		for i := range bindings {
			b := &bindings[i]
			plugin, ok := in.Sources.Lookup(b.SourceID)
			if !ok {
				if firstErr == nil {
					firstErr = fmt.Errorf("collector: source %q not registered for policy %q", b.SourceID, pp.Spec.ID)
				}
				continue
			}
			req := buildSlotRequest(pp, slotName, slot, b, in.SlotParamsExtras)
			records, err := plugin.Collect(ctx, req)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("collector: policy %q slot %q source %q: %w", pp.Spec.ID, slotName, b.SourceID, err)
				}
				continue
			}
			sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
			env := &core.Envelope{
				FormatVersion: EnvelopeFormatVersion,
				ProducedAt:    in.Now,
				Records:       records,
			}
			if err := sign.Envelope(env); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("collector: sign envelope for %q/%s/%s: %w", pp.Spec.ID, slotName, b.SourceID, err)
				}
				continue
			}
			path := envelopePath(in.RunRoot, pp.Spec.ID, slot.Type, b.SourceID, b.CatalogID)
			if err := in.Vault.PutEnvelope(ctx, path, env); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("collector: write envelope %s: %w", path, err)
				}
				continue
			}
			slotMap[slotName] = append(slotMap[slotName], records...)
			out.EnvelopesByPolicy[pp.Spec.ID] = append(out.EnvelopesByPolicy[pp.Spec.ID], path)
		}
	}
	out.RecordsByPolicy[pp.Spec.ID] = slotMap
	return firstErr
}

func buildSlotRequest(pp *planner.PlannedPolicy, slotName string, slot core.Slot, b *planner.Binding, extras map[string]any) core.SlotRequest {
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
		PolicyID:     pp.Spec.ID,
		EvidenceType: slot.Type,
		SlotName:     slotName,
		Params:       params,
	}
}

func envelopePath(runRoot, policyID, evidenceType, sourceID, catalogID string) string {
	suffix := sourceID
	if catalogID != "" {
		suffix = sourceID + "_" + catalogID
	}
	return fmt.Sprintf("%s/policies/%s/envelopes/%s__%s.json", runRoot, policyID, evidenceType, suffix)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
