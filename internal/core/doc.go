// Package core is L1 of the SigComply CLI: the frozen Go interfaces
// and structs that every higher layer depends on. Framework, Policy,
// EvidenceRecord, Envelope, Vault, Rule, SourcePlugin, CloudClient,
// SubmissionPayload, and their supporting value types live here.
//
// Once published these types are stable. The aggregation boundary
// (SubmissionPayload) is structurally counts-only and must not gain
// fields that could carry resource identifiers across L6.
//
// See docs/architecture/02-layers.md for the full layer contract.
package core
