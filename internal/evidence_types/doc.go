// Package evidencetypes holds the in-tree evidence-type schemas
// (JSON Schema documents) and exposes the loader that registers them
// into the orchestrator's EvidenceType registry at bootstrap.
//
// Evidence types are the contract that decouples policies from
// sources: a policy declares a slot Accepts a list of type IDs, a
// source plugin declares it Emits a list of type IDs, and the
// registry mediates. Two sources that both emit `user_record` are
// substitutable for any policy whose slot accepts `user_record` — no
// policy change required.
//
// Schemas live as JSON files under `schemas/`, embedded into the
// binary via go:embed. Each file is a JSON Schema draft-07 document
// with a `title` (the type ID) and `version` (a monotonic integer).
// Schemas are append-only: a breaking change requires a new ID
// (`user_record.v2`), never a mutation of an existing one.
//
// Project-local types under `.sigcomply/evidence_types/<id>.json`
// are compiled in by `sigcomply build` (M16) alongside the in-tree
// set. There is no runtime loading.
//
// Schema-conformance validation of collected payloads is performed by
// the collector (L4) using the Validator in this package; a missing
// or invalid payload surfaces as a configuration error (exit code 3).
//
// See docs/architecture/04a-evidence-type-registry.md.
package evidencetypes
