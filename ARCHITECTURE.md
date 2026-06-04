# SigComply CLI — Architecture

> **Status**: implemented. This document is the canonical design reference for
> the shipped v1 CLI (`sigcomply check`/`build`/`report`/`init-ci`/`evidence
> catalog`/`version`). Where a section describes a future capability it is
> marked inline; treat the code as the source of truth for what is wired.

SigComply is a zero-trust, non-custodial compliance engine. The CLI runs
inside the customer's own CI/CD environment, evaluates compliance policies
against their infrastructure, signs every piece of evidence locally, and —
only when the customer opts in — sends *aggregated counts* (never raw
evidence) to a hosted dashboard. The product positioning is "evidence
without access."

This document is the top-level map. Detailed design lives in the
[`docs/architecture/`](docs/architecture/) tree.

## Free CLI / paid cloud — the product split

The product ships as two intentionally decoupled pieces:

- **The CLI (open source, free)** — what this document specifies. Runs
  per-invocation: collect → check → write vault → submit counts. Stateless;
  no DB; no shared state across runs. Snapshot reporting against the vault
  (`sigcomply report --view latest|exceptions|integrity`).
- **SigComply Cloud / Rails app (paid)** — receives per-run aggregated
  counts via the privacy-preserving `SubmissionPayload`, stores them over
  time in a Rails-backed DB (stripped of all sensitive information per the
  aggregation contract), and provides the **longitudinal analytical layer**:
  deviation timelines, drift detection, continuous-monitoring alerts,
  auditor-ready Type II reports, multi-project rollups, auditor seats.

The vault is the customer's data layer for both. The CLI is the writer.
The paid Rails app is the index + analytics layer over the time-series of
submissions; it never holds raw evidence or identifiers — those stay in
the vault on the customer's side of the privacy boundary.

A customer who declines the paid cloud still has a fully functional
compliance system: the CLI writes evidence to their vault, `sigcomply
report` produces snapshot views, the reference verifier proves
integrity. What they don't have is the throughout-period narrative
(Type II "operated effectively throughout") or alerts — those require
either a paid Rails subscription, a self-hosted Rails (if offered), or
custom analytics against the vault.

See [`docs/architecture/06-aggregation.md`](docs/architecture/06-aggregation.md)
§What the paid Rails app does with the submitted data.

---

## Core principles (non-negotiable)

These hold across every layer. Any change that violates one of them
requires going back to the drawing board.

1. **The aggregation boundary is sacred.** No resource identifier ever
   leaves the customer environment. The cloud submission struct is
   *physically incapable* of carrying ARNs, emails, usernames, file
   hashes, or any other identity — only counts, statuses, and policy IDs.
2. **The CLI is stateless across runs.** Every `sigcomply check`
   invocation reads the project config and the external sources it's
   bound to. It never reads prior runs from the vault, never consults
   a database, never carries in-memory state from a prior invocation.
   Cadence enforcement ("did the quarterly policy already run?") is the
   CI scheduler's job, not the CLI's — see
   [`docs/architecture/10-ci-execution-model.md`](docs/architecture/10-ci-execution-model.md).
3. **The vault is append-only.** Each run writes its own immutable
   folder. Period-level state is *derived* from the union of runs in a
   period, not stored as an authoritative mutable file. There is no
   read-modify-write on shared state.
4. **Every evidence file is independently verifiable.** Per-file
   ephemeral Ed25519 signing. Private key generated at write time,
   discarded immediately. An auditor with a single envelope file and the
   public key embedded in it can verify the file offline, with no access
   to the CLI, the cloud, or any other piece of state.

   **What this guarantees, and what it doesn't.** Embedded-public-key
   signing detects accidental drift and unilateral PDF swaps (the
   manifest's `file_hash` won't match new bytes). It does **not**
   detect a customer with vault write access who regenerates envelope
   + PDF together with a fresh ephemeral keypair — that re-signing
   is cryptographically indistinguishable from original collection.
   True tamper-resistance against deliberate re-signing requires
   write-once / versioned object storage at the bucket layer (S3
   Object Lock in compliance mode, GCS Bucket Lock with retention,
   Azure Blob immutable storage). This is a customer-side setup
   responsibility; the CLI does not configure it. See
   [`SECURITY.md`](SECURITY.md) §Threat Model and CLAUDE.md Invariant
   #3 for the precise wording to use in customer-facing docs.
5. **Evidence type ≠ source plugin.** A policy depends on an evidence
   *shape* (`user_record`, `firewall_rule`). Many source plugins can
   produce the same shape. Policies never reach behind the type to ask
   which plugin produced it; this is what makes sources interchangeable
   per project.
6. **Each policy fetches its own data.** No shared collection layer
   across policies. If ten policies all need AWS IAM users, that's ten
   independent fetches. Maximally self-contained policies; runtime cost
   is the explicit trade-off.
7. **Determinism wherever possible.** Given the same inputs (sources'
   responses + config + timestamp), a run produces byte-identical
   outputs modulo explicit timestamps. Auditors diff runs.
8. **Project config is the customer's source of truth.** Framework
   selection, source bindings, exceptions, parameter overrides, fiscal
   calendar, cadence overrides — all live in `.sigcomply.yaml`,
   versioned in git. The vault carries evidence; git carries decisions.
9. **One project = one source-control repository = one framework.** A
   project corresponds to exactly one repo (GitHub or GitLab) and that
   project pursues exactly one compliance framework. Customers pursuing
   multiple frameworks typically use multiple repos. The CI workflow
   files live in the repo and are part of the audit trail.

---

## The layered architecture at a glance

```
┌────────────────────────────────────────────────────────────────────┐
│  L9  Orchestrator     CLI entry point; CI integration; exit codes  │
├────────────────────────────────────────────────────────────────────┤
│  L8  Submitter        Optional cloud submission (counts only)      │
├────────────────────────────────────────────────────────────────────┤
│  L7  Persistence      Vault writes (envelopes, results, summaries) │
├────────────────────────────────────────────────────────────────────┤
│  L6  Aggregator       Privacy boundary; counts-only schema         │
├────────────────────────────────────────────────────────────────────┤
│  L5  Evaluator        Run each policy's rule with its evidence     │
├────────────────────────────────────────────────────────────────────┤
│  L4  Collector        Per-policy fetches; envelope signing         │
├────────────────────────────────────────────────────────────────────┤
│  L3  Planner          Resolve bindings; ordered policy list        │
├────────────────────────────────────────────────────────────────────┤
│  L2  Registries       Framework, Source, Rule, EvidenceType lookups│
├────────────────────────────────────────────────────────────────────┤
│  L1  Core domain      Stable Go types and interfaces               │
├────────────────────────────────────────────────────────────────────┤
│  L0  Specifications   Framework specs, policy specs, ET schemas,   │
│                       project config (data-as-code, all versioned) │
└────────────────────────────────────────────────────────────────────┘
```

Detailed layer responsibilities: [`02-layers.md`](docs/architecture/02-layers.md).

---

## Vocabulary

Used consistently across every doc and every line of code. Full
definitions in [`01-conceptual-model.md`](docs/architecture/01-conceptual-model.md).

| Term | One-line meaning |
|---|---|
| **Framework** | A published compliance regime (SOC 2, ISO 27001, HIPAA). |
| **Control** | A single requirement in a framework, e.g. `SOC2.CC6.1`. |
| **Policy** | A verifiable assertion contributing to a control. |
| **Policy cadence** | How often a policy must be evaluated (`continuous` … `annual`); drives CI scheduling. |
| **Rule** | The logic deciding a policy's outcome from its evidence inputs. |
| **Source** | Something producing evidence (`aws.iam`, `okta`, `manual.pdf`). |
| **Evidence type** | The *shape* of a piece of evidence; a versioned schema. |
| **Slot** | A named, typed input on a policy. |
| **Binding** | Project-level mapping of slot → source(s). |
| **Evidence record** | One fulfilled piece of data. |
| **Envelope** | Signed wrapper around a batch of evidence records. |
| **Period** | A first-class audit window (e.g. `2026-Q1`). |
| **Run** | One CLI invocation. Owns a run ID, stamped period, commit. |
| **Vault** | Customer-owned storage receiving envelopes, results, summaries. |
| **Project** | The customer's deployment (config + vault + bindings). |

---

## Document map

| Doc | What it covers |
|---|---|
| [`00-three-plugin-axes.md`](docs/architecture/00-three-plugin-axes.md) | The unified design principle: three orthogonal plugin axes (manual input storage, output vault storage, API sources) all use one self-registering factory pattern. Read this first to grok the extensibility story. |
| [`01-conceptual-model.md`](docs/architecture/01-conceptual-model.md) | The sixteen abstractions, their relationships, and the substitutability axioms (1–6) that make the design extensible. |
| [`02-layers.md`](docs/architecture/02-layers.md) | Each layer's responsibilities, interfaces, and the contracts between them. |
| [`03-policy-spec.md`](docs/architecture/03-policy-spec.md) | Format of a policy spec; slots, parameters, rule references; examples in Rego, Go, and YAML DSL. |
| [`04-source-plugins.md`](docs/architecture/04-source-plugins.md) | Source plugin contract; how to author one; how evidence types are declared and consumed. |
| [`05-vault-layout.md`](docs/architecture/05-vault-layout.md) | Vault directory structure; envelope format; signing; versioning. |
| [`06-aggregation.md`](docs/architecture/06-aggregation.md) | The privacy boundary in detail; the exact wire format; structural enforcement. |
| [`07-extensibility.md`](docs/architecture/07-extensibility.md) | How customers add custom policies and custom source plugins; how the community contributes upstream. |
| [`08-project-config.md`](docs/architecture/08-project-config.md) | Full `.sigcomply.yaml` schema reference. |
| [`09-implementation-roadmap.md`](docs/architecture/09-implementation-roadmap.md) | Order of work, milestones, what ships when. |
| [`10-ci-execution-model.md`](docs/architecture/10-ci-execution-model.md) | How the CLI fits into a CI pipeline; cadence-driven workflow scheduling; `sigcomply init-ci` scaffolding; how statelessness survives variable run frequencies. |
| [`11-cadence-model.md`](docs/architecture/11-cadence-model.md) | The two-axis cadence model (per-policy gating vs per-run period freeze); per-policy state shards; the `every:<duration>` DSL; carry-forward result format; day-1 warnings; the per-policy cadence scalars in the cloud payload. The canonical reference for "should this policy re-evaluate now?" |
| [`examples/acmecorp-walkthrough.md`](docs/architecture/examples/acmecorp-walkthrough.md) | End-to-end worked example: AcmeCorp pursuing SOC 2 with AWS + Okta + manual evidence. Reads alongside [`examples/acmecorp.sigcomply.yaml`](docs/architecture/examples/acmecorp.sigcomply.yaml). |

---

## Reading order

- **First pass (1 hour)**: this file → `00-three-plugin-axes.md` →
  `01-conceptual-model.md` → `examples/acmecorp-walkthrough.md`.
  You'll understand the extensibility story, the model, and see it
  applied end to end.
- **Implementing a layer**: this file → `02-layers.md` → the spec for
  the layer's inputs/outputs (e.g. `03-policy-spec.md` if you're
  implementing the planner).
- **Adding a source plugin**: `04-source-plugins.md` →
  `07-extensibility.md`.
- **Defining a custom policy**: `03-policy-spec.md` →
  `08-project-config.md`.
- **Auditor / compliance reviewer**: this file → `06-aggregation.md`
  (proves the privacy story) → `05-vault-layout.md` (proves the
  verification story).
