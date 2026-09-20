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

// SourceCaveat is a plugin's own declaration that a field it emits is not
// really observed — the vendor publishes no API for it, or the credential
// cannot reach the one that exists — so the value is a safe default rather
// than a measurement.
//
// It exists because the planner binds EVERY configured source whose Emits()
// intersects a slot, and every ordinary slot is one-or-more, so cardinality
// never forces a choice. On the common estate — an IdP SCIM-synced into AWS
// Identity Center — both sources bind the MFA policies and their records are
// unioned: every Identity Center user fails on a hardcoded false while the
// Okta records beside them carry the true answer for the same humans. Nothing
// in the run says so. A caveat lets the planner say so.
//
// This is a source declaring its OWN limits, which is why it does not breach
// Invariant #4: no policy branches on a source ID, and no plugin learns which
// policy consumes it. The planner joins the two by evidence type and field
// name — the same contract that already mediates binding.
//
// It is advisory only. A caveat never changes a status, a count, or the wire
// payload: "integration health" was considered as a result axis and rejected
// (a degraded read is an operator problem to fix now, not a grade to report).
type SourceCaveat struct {
	// EvidenceType is the type ID the caveat applies to, e.g. "directory_user".
	EvidenceType string
	// Field is the payload field name, without the "payload." prefix,
	// e.g. "mfa_enabled".
	Field string
	// Detail says what the plugin actually emits and why, in one sentence an
	// operator can act on. It must be honest about whether the limit is
	// absolute (no API exists) or conditional (this credential cannot read it).
	Detail string
}

// CaveatedSource is the optional interface a SourcePlugin implements to
// declare its SourceCaveats. Optional by design: a plugin that implements
// nothing declares no caveats, which is the correct default and cannot break
// a plugin that predates the interface.
//
// Anything wrapping a SourcePlugin must forward this method — see
// sources.instancePlugin, where a missed forward would silently drop every
// caveat for bracketed instance keys.
type CaveatedSource interface {
	Caveats() []SourceCaveat
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
