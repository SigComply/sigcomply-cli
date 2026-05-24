# 00 — The Three Plugin Axes

SigComply's extensibility rests on **three orthogonal plugin axes**.
Each axis is independently substitutable. A customer (or a third-party
contributor) can swap one without touching the others, and **the core
CLI codebase does not need to be edited** to add a new plug-in along
any of the three. This is the central design principle the rest of the
architecture is built to preserve.

This document is the unified story. The per-axis details live in
[`04-source-plugins.md`](04-source-plugins.md),
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md),
[`05-vault-layout.md`](05-vault-layout.md), and
[`07-extensibility.md`](07-extensibility.md).

---

## Why three axes — and not one, not five

Every compliance check the CLI runs is the same shape: **fetch
evidence → evaluate against policy → write the signed result to a
vault**. Each of those three verbs touches an external system the
customer owns and the CLI does not:

1. **Fetching evidence from third-party APIs** (Axis C). AWS, GCP,
   GitHub, Okta, Azure AD, a customer's internal LDAP, a SaaS vendor
   nobody at SigComply has heard of yet — every API source needs its
   own fetch logic and its own response shape. The customer chooses
   which sources cover their environment.
2. **Fetching manual evidence (PDFs) from the customer's storage**
   (Axis A). The customer uploads quarterly access reviews, signed
   NDAs, training certificates, declarations of risk acceptance, etc.,
   to a bucket they own. Different customers use different buckets:
   AWS S3, GCS, Azure Blob, on-prem MinIO, a private SFTP server,
   plain NFS.
3. **Writing signed evidence + results + manifests to the customer's
   vault** (Axis B). Same three or four object stores, same on-prem
   options, but used for *writing* the output of a run rather than
   reading manual evidence.

The substitutable axis in each case is the **system on the customer's
side of the privacy boundary**. SigComply ships sensible defaults for
the popular options (S3 / GCS / Azure / local), but the design must
accept that real customers will want backends nobody anticipated. The
three axes are the three places that contract lives.

A fourth axis (custom policies) exists too — see
[`07-extensibility.md`](07-extensibility.md) — but policies are a
different kind of artifact (they consume the three axes; they aren't
one of them).

---

## The three axes at a glance

| Axis | What's pluggable | Read or write? | What stays the same regardless of plug-in |
|---|---|---|---|
| **A** | Manual evidence input storage | Read | The path scheme (`{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/{filename}`), presence + temporal-window check, signed `signed_document` envelope shape |
| **B** | Output vault storage | Write | The `core.Vault` interface, the per-run folder layout, the signed manifest, every byte of envelope content |
| **C** | API-based data sources | Read | The `SourcePlugin` interface (`Emits() / Collect()`), the embedded JSON-Schema-validated evidence record shape, the planner's `slot.Accepts ∩ source.Emits ≠ ∅` matching |

The promise the customer reads off this table is:

> *For every compliance check in every framework, the surrounding
> machinery — fetch path, signature, schema validation, vault layout,
> aggregation contract — is identical. Only the **leaf plug-in** on
> the customer's side differs.*

---

## Axis A — Manual evidence input storage

**The substitution claim.** For manual evidence, the customer chooses
the storage backend their PDFs live in. The CLI reads from it
identically regardless of which backend it is.

**The contract.** A backend is anything that satisfies the
`manual.Reader` interface (`internal/sources/manual/manual.go`):

```go
type Reader interface {
    Get(ctx context.Context, uri string) (data []byte, uploadedAt time.Time, err error)
}
```

The path scheme `{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/{filename}`
is the same regardless of backend, so the policy layer (which only
checks presence within the temporal window) is identical for every
customer and every framework.

**The plug-in mechanism.** `internal/sources/manual` exposes a
self-registering factory registry:

```go
func RegisterReader(id string, f ReaderFactory)
```

Each in-tree backend's `init()` calls `RegisterReader`. The `manual.pdf`
source's `buildReader` dispatches by config-string lookup — no hardcoded
switch, no per-backend knowledge in the plugin core.

**Status.** The `local` filesystem backend ships and is wired today.
Cloud backends (S3, GCS, Azure Blob) and any third-party backend (SFTP,
MinIO, NFS, custom object stores) plug in via `RegisterReader` from
their own subpackage — no edits to `internal/sources/manual`. The
shipped cloud backends land alongside the post-M6 plugin-set work; the
registry pattern they will register against is in place today.

See [`04-source-plugins.md`](04-source-plugins.md) §The manual.pdf
plugin and [`07-extensibility.md`](07-extensibility.md) §Custom
manual-evidence backends.

---

## Axis B — Output vault storage

**The substitution claim.** For the vault — the customer-owned storage
that receives every signed evidence envelope, every PDF mirror, every
per-policy `result.json`, every per-run `manifest.json` — the customer
chooses the backend. The CLI writes to it identically regardless of
which backend it is.

**The contract.** A backend is anything that satisfies the `core.Vault`
interface (`internal/core/vault.go`):

```go
type Vault interface {
    Init(ctx context.Context) error
    PutEnvelope(ctx context.Context, key string, e *Envelope) error
    PutJSON(ctx context.Context, key string, body any) error
    PutBinary(ctx context.Context, key string, body []byte, meta map[string]string) error
    GetBinary(ctx context.Context, key string) ([]byte, error)
    List(ctx context.Context, prefix string) ([]string, error)
}
```

The L4 (Collector), L7 (Persistence), and L8 (Submitter) layers consume
`core.Vault` abstractly — they never know or care which backend is
behind it.

**The plug-in mechanism.** `internal/vault` exposes a self-registering
factory registry:

```go
func RegisterBackend(id string, f Factory)
```

Each in-tree backend's `init()` calls `RegisterBackend`.
`internal/vault/builtin` blank-imports all four backends; the
orchestrator blank-imports `vault/builtin` and `vault.FromConfig`
dispatches by config-string lookup — no hardcoded switch, no
per-backend knowledge in the factory.

**Status.** Four backends ship and are wired today: `local`, `s3`,
`gcs`, `azure_blob`. The `s3` backend also serves on-prem
S3-compatible stores (MinIO, Ceph, …) via `endpoint` +
`force_path_style`. Any third-party backend (SFTP, NFS, custom object
stores, a fully internal protocol) plugs in via `RegisterBackend` from
its own package — compiled in by `sigcomply build` (M16) for
project-local plug-ins, or by a stand-alone fork for upstream
contributions.

See [`05-vault-layout.md`](05-vault-layout.md) §Backend abstraction
and [`07-extensibility.md`](07-extensibility.md) §Custom vault
backends.

---

## Axis C — API-based data sources

**The substitution claim.** A policy declares the *shape* of evidence
it needs (an evidence type). Any source plugin that can produce that
shape satisfies the policy. Two customers can satisfy the same policy
with different sources; one customer can mix sources for the same
policy.

**The contract.** A source is anything that satisfies the
`core.SourcePlugin` interface (`internal/core/source.go`):

```go
type SourcePlugin interface {
    ID() string
    Emits() []string
    Init(ctx context.Context, cfg map[string]any) error
    Collect(ctx context.Context, req SlotRequest) ([]EvidenceRecord, error)
}
```

The shape every emitted record must match is a **versioned JSON Schema
embedded into the binary** under `internal/evidence_types/schemas/`.
The collector validates every emitted payload against the registered
schema before signing — a schema-conformance failure is a configuration
error (exit 3).

The planner binds a source to a slot when

```
source.Emits() ∩ slot.Accepts ≠ ∅
```

A policy never names a source ID; a source never names a policy ID
(`SlotRequest.PolicyID` is diagnostic-only). The evidence-type registry
is the **sole** coupling point — Sacred Invariant #4 in
[`../../CLAUDE.md`](../../CLAUDE.md).

**The plug-in mechanism.** `internal/sources` exposes a
self-registering factory registry:

```go
func RegisterFactory(id string, f Factory)
```

Each in-tree source's `init()` calls `RegisterFactory`.
`internal/sources/builtin` blank-imports all in-tree sources;
`cmd/sigcomply` blank-imports `sources/builtin` and dispatches by
config-string lookup.

**Status.** Many in-tree sources ship today (AWS across IAM/S3/EC2/RDS/
KMS/CloudTrail/CloudWatch/Config/EKS/GuardDuty/…; GCP across
IAM/Storage/Compute/SQL; GitHub; Okta). The evidence-type schemas for
the records they emit (e.g. `user_record`, `s3_bucket`, `signed_document`)
are embedded via `go:embed` and validated at collection time. Third
parties add custom sources via `RegisterFactory` from their own
package — compiled in by `sigcomply build` (M16) for project-local
plug-ins, or by upstream PR.

See [`04-source-plugins.md`](04-source-plugins.md),
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md), and
[`07-extensibility.md`](07-extensibility.md) §Authoring a custom
source plugin.

---

## The shared mechanism

All three axes implement the **same self-registering factory pattern**.
Concretely, every plug-in package has this shape:

```go
package myplugin

import "<host-registry-package>"

func init() {
    host.RegisterX("my-id", build)
}

func build(/* host-specific args */) (HostInterface, error) {
    // construct + Init the implementation
}
```

And the host package never names any plug-in — only the registry
function, the Lookup, and the IDs() helper for error messages. Adding
a plug-in is, in every case:

1. Drop the plug-in package under `internal/<host>/<id>/` for in-tree
   or `.sigcomply/plugins/<id>/` for project-local.
2. Write an `init()` that calls `RegisterX`.
3. For in-tree: add one blank-import line to `internal/<host>/builtin/`.
   For project-local: `sigcomply build` (M16) generates the equivalent
   import list into the project-tailored binary.

That's it. No core edits in any layer. No runtime plugin loading. No
shared library, no DSL beyond the existing rule DSLs, no IPC, no WASM.

---

## What the three axes do **not** make pluggable

These are explicitly *not* extension points — they're contracts
external parties (auditors, the cloud, the verification SPA) rely on:

- **Framework specs.** Customers add custom *policies* (Axis-D-ish, see
  [`07-extensibility.md`](07-extensibility.md)); they cannot publish a
  custom "SOC 2" framework spec.
- **The aggregation contract.** The wire format crossing the privacy
  boundary to the cloud dashboard is structurally counts-only. Widening
  it requires an upstream code change and a security review — never a
  plug-in.
- **Vault directory layout and envelope format.** Schemas are fixed
  within a major version; a custom Axis-B backend writes the same
  bytes, just to a different physical store.
- **Evidence-type schemas already shipped.** Plug-ins can add *new*
  evidence types but cannot redefine existing ones in incompatible
  ways. Breaking changes require a new ID (`user_record.v2`).

The substitutability axioms in [`01-conceptual-model.md`](01-conceptual-model.md)
§The substitutability axioms restate these consequences in
load-bearing form.
