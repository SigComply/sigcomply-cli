// Package spec is L0 of the SigComply CLI: parsers and validators for
// the declarative artifacts that drive the engine — framework specs,
// policy specs, evidence type schemas, source plugin manifests, the
// project config (.sigcomply.yaml), and the manual evidence catalog.
//
// L0 owns the on-disk format. Nothing here executes; specs are read,
// validated, and handed up to L1 (types) and L2 (registries).
//
// See docs/architecture/02-layers.md for the full layer contract.
package spec
