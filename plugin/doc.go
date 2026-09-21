// Package plugin is the public API a project-local Go extension
// compiles against. It is the only non-internal Go package in this
// module, and it exists for one narrow reason.
//
// Go refuses an import of a path containing an "internal" element from
// outside the tree rooted at that element's parent. `sigcomply build`
// compiles a customer's .sigcomply/ extensions inside the CUSTOMER's
// module — readModulePath in cmd/sigcomply/build.go reads the project's
// own go.mod, and `go build` runs from the project directory. So every
// interface and registry a Go extension has to reach — core.SourcePlugin,
// sources.RegisterFactory, vault.RegisterBackend, manual.RegisterReader —
// sat behind a wall the customer could not climb: their package passed
// `sigcomply build`'s discovery, validation and vet, and then failed the
// compile that same command triggered, with "use of internal package …
// not allowed". Authoring a Go plugin project-locally meant forking the
// CLI. This package is the door, and nothing more than the door.
//
// # Everything here is a compatibility promise
//
// A re-export is a commitment: it is what customers compile against and
// what a major version has to keep working (see
// docs/architecture/07-extensibility.md §Compatibility guarantees). The
// surface is therefore deliberately small — exactly what the three
// plugin axes documented in docs/architecture/00-three-plugin-axes.md
// need, and not one identifier more. Adding to it is a decision, not a
// convenience; the cost of a too-wide façade is paid years later, by
// whoever cannot change an internal type because someone once found it
// handy here.
//
//   - Axis C, source plugins: SourcePlugin, Env, SourceFactory,
//     RegisterSource, plus the evidence values a Collect implementation
//     must name (SlotRequest, EvidenceRecord, RecordScope) and the
//     optional caveat interface (CaveatedSource, SourceCaveat).
//   - Axis B, vault backends: Vault, Envelope, VaultConfig,
//     VaultFactory, RegisterVaultBackend.
//   - Axis A, manual-evidence backends: ManualReader, ManualFileInfo,
//     ManualReaderFactory, RegisterManualReader, ErrManualNotFound.
//
// # Aliases, not wrappers
//
// Every type here is a type ALIAS of the internal type, so a value
// written against this package IS the internal type — identical, not
// convertible. A plugin built through RegisterSource satisfies
// core.SourcePlugin with no adapter, records it emits are the same
// structs the collector validates, and no copy-and-translate layer
// exists to fall out of step. The registration functions are thin
// forwarders only because Go has no such thing as a function alias;
// they add no behavior, and plugin_test.go asserts that a registration
// made here lands in the registry the orchestrator actually reads.
//
// # What is deliberately NOT public
//
//   - Frameworks, policies, the pass_when DSL, the evaluator and the
//     rule registry. Framework specs are curated — an auditor has to
//     trust that the SOC 2 spec being measured against is the canonical
//     one. Custom policies are authored as project-local YAML, and
//     custom rule logic as Rego; neither needs Go.
//   - Evidence types. They are registered from JSON Schema — embedded
//     in-tree, or project-locally from .sigcomply/evidence_types/*.json
//     — and never from a Go init(). There is no hook to expose.
//   - The aggregation contract (core.SubmissionPayload and friends).
//     That is the privacy boundary: the wire type is structurally
//     incapable of carrying identifiers, and widening it is an upstream
//     change with a security review, never a customer extension.
//   - The vault layout, the manifest, and the signing keys. Auditors and
//     the verification SPA depend on those shapes being fixed.
//   - The host side of each registry — sources.Build, sources.Lookup,
//     sources.IDs, vault.FromConfig, manual.LookupReader. An extension
//     registers itself; it never dispatches, enumerates or replaces its
//     peers. Keeping the read side internal is what stops a plugin from
//     quietly reaching across the seam into another one.
//   - Convenience helpers that happen to be exported internally
//     (sources.StringOpt, the instance-ID grammar, core.EnvelopeSignature).
//     They are one-line idioms or fields reachable through a value that
//     is already public; promising them forever buys nothing.
//
// If something you need is missing, that is a conversation about the
// contract, not a gap to route around: open an issue rather than
// vendoring or forking. The data-driven routes (YAML policies, Rego
// rules, JSON evidence types) need no Go at all and load at every
// `sigcomply check` — reach for those first.
package plugin
