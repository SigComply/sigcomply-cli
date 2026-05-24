package core

import "context"

// SourcePlugin produces EvidenceRecords for slots it can fulfill.
// Shipped plugins are compiled in; project-local plugins under
// .sigcomply/plugins/ are compiled in by `sigcomply build` (M16).
//
// Implementations must:
//  1. Sort emitted records by ID lexicographically before returning
//     from Collect — keeps envelope bytes stable across runs when
//     source state is stable.
//  2. Set IdentityKey on EvidenceRecord when the evidence type has a
//     meaningful cross-source identity (see 03-policy-spec.md
//     §Cross-source dedup).
//  3. Avoid embedding wall-clock timestamps in record payloads beyond
//     what the source itself provides; use EvidenceRecord.CollectedAt
//     for fetch time.
type SourcePlugin interface {
	ID() string
	Emits() []string
	Init(ctx context.Context, cfg map[string]any) error
	Collect(ctx context.Context, req SlotRequest) ([]EvidenceRecord, error)
}

// SlotRequest is the per-binding call into a plugin's Collect.
//
// PolicyID is for diagnostics only — plugins must not branch behavior
// on it. AcceptedTypes is the intersection of the slot's Accepts list
// with the plugin's Emits(); the plugin returns records of any
// AcceptedTypes element (typically just one, since most plugins emit a
// single type). The planner enforces non-empty intersection at plan
// time, so AcceptedTypes is always at least one element on a real
// invocation. Params carries optional per-binding slot_params from the
// project config (rare; most bindings have no params).
type SlotRequest struct {
	PolicyID      string
	AcceptedTypes []string
	SlotName      string
	Params        map[string]any
}

// Accepts reports whether typeID is one of the slot's accepted
// evidence types. Source plugins use it to dispatch on which of
// their emitted types the slot actually wants.
func (r SlotRequest) Accepts(typeID string) bool {
	for _, t := range r.AcceptedTypes {
		if t == typeID {
			return true
		}
	}
	return false
}
