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
	Collect(ctx context.Context, slot string) ([]EvidenceRecord, error)
}
