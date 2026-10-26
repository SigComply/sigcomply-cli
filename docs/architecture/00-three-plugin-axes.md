# 00: The three plugin axes

Every check reads evidence from a system the customer owns and writes signed results to storage
the customer owns. The CLI makes each of those external systems a plug-in, so adding one never
edits core code. There are three axes, plus custom policies, which consume the axes rather than
being one.

| Axis | What plugs in | Go interface | In-tree registry | In-tree backends (blank-imported by) | Owner doc |
|---|---|---|---|---|---|
| A | Manual-evidence input storage (read) | `manual.Reader` (`internal/sources/manual/manual.go`) | `manual.RegisterReader` | `local` (registered in `manual/factory.go`), `s3`, `gcs`, `azure_blob` (`internal/sources/manual/builtin`) | [04 §The manual.pdf plugin](04-source-plugins.md#the-manualpdf-plugin), [07](07-extensibility.md) |
| B | Output vault (write) | `core.Vault` (`internal/core/vault.go`) | `vault.RegisterBackend` | `local`, `s3`, `gcs`, `azure_blob` (`internal/vault/builtin`) | [05](05-vault-layout.md), [07](07-extensibility.md) |
| C | API data sources (read) | `core.SourcePlugin` (`internal/core/source.go`) | `sources.RegisterFactory` | every plugin under `internal/sources/` (`internal/sources/builtin`) | [04](04-source-plugins.md), [04a](04a-evidence-type-registry.md) |

All three use the same self-registering factory pattern. [04 §The factory
contract](04-source-plugins.md#the-factory-contract) explains it once; don't restate it elsewhere.

## Axis A: manual-evidence input storage

The customer picks where uploaded documents live. The folder scheme, the file checks and the
`signed_document` record are the same for every backend. The `s3` backend also serves
S3-compatible stores through `endpoint` and `force_path_style`. Project-local backends register
with `plugin.RegisterManualReader`.

## Axis B: output vault storage

The customer picks where envelopes, `result.json`, `summary.json` and `manifest.json` go. Every
backend writes the same bytes to the same paths. Consumers of `core.Vault` are
`internal/collector`, `internal/orchestrator` and `internal/report`; `cmd/sigcomply` blank-imports
`internal/vault/builtin`, and `vault.FromConfig` dispatches by backend ID. Project-local backends
register with `plugin.RegisterVaultBackend`.

## Axis C: API data sources

A policy names evidence types; a plugin emits evidence types; the evidence-type registry is the
only join (`source.Emits() ∩ slot.Accepts`). Neither side names the other (Sacred Invariant #4 in
[`AGENTS.md`](../../AGENTS.md)). Project-local sources register with `plugin.RegisterSource`.

## Project-local plug-ins

Customer code lives under `.sigcomply/plugins/<id>/` and is compiled in by `sigcomply build`. It
runs in the customer's Go module, where `internal/` is not importable, so it registers only
through the public `plugin/` package (`plugin/plugin.go`). There is no runtime plugin loading.
Walkthrough: [07-extensibility.md](07-extensibility.md).

## Not pluggable

- Framework specs. Customers add policies, not frameworks.
- The aggregation contract (`core.SubmissionPayload`). Widening it is a code change and a
  security review ([06](06-aggregation.md)).
- The vault layout and envelope format ([05](05-vault-layout.md)).
- Shipped evidence-type schemas. A breaking change is a new version
  ([04a](04a-evidence-type-registry.md)).
