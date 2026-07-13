# Concepts

Why SigComply is built the way it is — the non-custodial model, the aggregation boundary, evidence signing, and the source-agnostic evidence model.

Back to the [documentation hub](README.md).

## Evidence without Access

Traditional compliance platforms ask you to hand over credentials or install an agent that reads your production data into their cloud. SigComply inverts that. The CLI is a Go binary that runs **inside your own CI/CD**, uses **your own** read-only credentials, and writes every piece of raw evidence into **your own** storage. The vendor never gets access to your infrastructure, your data, or the identities within it. This is what "Evidence without Access" means and why the model is called **non-custodial**: SigComply is never the custodian of your raw evidence.

The practical consequence is a hard boundary between what stays with you and what — if you opt into the paid cloud tier — leaves.

## The aggregation boundary

The CLI is the **only** place raw evidence is reduced to counts. Everything that could identify a person or resource is aggregated away before anything is sent anywhere.

**Stays in your storage, forever:** raw API responses, PDF bytes, full violation lists with identifiers (ARNs, emails, usernames, account IDs), the ephemeral public keys and signatures, and the per-run `manifest.json`.

**The only thing that leaves** (and only if you enable cloud submission): aggregated per-policy counts and pass/fail scores.

The canonical example:

```
Stored in the cloud:   mfa_disabled_count: 3
NEVER stored:          "users alice, bob, and carol have MFA disabled"
```

The dashboard learns that three resources failed a check — never which three. The submission type is designed so it *physically cannot* carry identity: there is no free-form map and no violations list on the wire, and the Rails dashboard enforces a second allow-list on top. If you want to know *which* resources failed, you read the full violation list in your own vault — it never left.

## The two evidence flows

Every policy declares exactly one of two evidence flows via `evidence_mode`.

- **Automated** (`evidence_mode: automated`) — an API source plugin collects JSON from a provider (AWS, GCP, Azure, GitHub, GitLab, Okta) using your read-only credentials. The records are validated against an evidence-type schema, then evaluated by the declarative `pass_when` DSL. Example: "every IAM user has MFA enabled."

- **Manual** (`evidence_mode: manual`) — for evidence that can't come from an API (a signed NDA, a quarterly access-review export, a training certificate). You upload one or more files to a folder in your bucket; the CLI scans the folder, converts images to PDF, merges everything into one PDF, and runs a **presence** check: is a valid PDF present within the audit period's temporal window? The CLI deliberately does **not** read the PDF's contents — no text extraction, no signature parsing. Reviewing what the document actually says is the auditor's job.

There are only these two flows. The catalog `type` values (`document_upload`, `declaration`, `checklist`) are rendering hints for the optional [Evidence SPA](guides/verify-evidence.md); the CLI evaluator does not branch on them. See [the two evidence flows in depth](architecture/01-conceptual-model.md).

## The vault and evidence signing

`check` writes results to your **vault** — your own storage backend (`local`, `s3`, `gcs`, or `azure_blob`). For each evidence file it writes an **EvidenceEnvelope**: the canonical JSON of `{timestamp, evidence}` signed with a **fresh, per-file, ephemeral Ed25519 keypair**. The private key is discarded the instant the signature is computed; the public key and signature are embedded in the envelope itself, so each file is independently verifiable. Each run also writes a `manifest.json` listing the SHA-256 hashes of every file (a single-level Merkle set), itself signed with its own ephemeral keypair — so one signature covers the integrity of the whole run while each file stays independently spot-checkable. A manual PDF is stored alongside the run and referenced by its SHA-256 hash.

An auditor can take any single signed envelope and verify it in a browser with the [Evidence SPA `/verify` page](guides/verify-evidence.md) — no server, no account.

### An honest word on tamper-resistance

The signing scheme detects **accidental corruption** and a **swapped PDF** (the manifest hash stops matching). It does **not**, on its own, stop deliberate tampering: because the public key lives inside the envelope, someone with write access to the vault can regenerate an envelope and PDF with a brand-new keypair, and the result is indistinguishable from an original. The CLI signs what it reads — it cannot tell fabricated-at-upload evidence from genuine.

Real tamper-resistance requires **write-once / versioned storage at the storage layer**, which you configure yourself:

- **S3** — Object Lock, or versioning + MFA delete
- **GCS** — Object Versioning with retention, or Bucket Lock
- **Azure** — immutable blob storage

The CLI does **not** configure any of this, and local filesystem vaults are dev/CI-ephemeral only. Without write-once storage the scheme still catches accidental drift, but not deliberate re-signing. Don't claim more than that to your auditor. Full design: [signing and vault layout](architecture/05-vault-layout.md).

## Source-agnostic policies: one policy, many providers

Policies and source plugins never reference each other. A policy declares the **evidence types** it accepts; a source plugin declares the evidence types it **emits**. An evidence-type registry — versioned JSON Schemas — is the only thing in between. The planner binds a source to a policy when their types intersect.

The payoff is substitutability. A single "MFA enforced on admins" policy is satisfied by AWS IAM, Okta, Azure AD, or an internal directory — whichever emits the matching evidence type — with **zero** changes to the policy. Adding a new provider for an evidence type you already check is a one-line configuration change, not a policy fork. The conventional slot name a policy binds against is `evidence`. Full design: [evidence-type registry](architecture/04a-evidence-type-registry.md).

## See also

- [Frameworks](reference/frameworks.md) — how policies map to controls.
- [Verify evidence](guides/verify-evidence.md) — report views and the `/verify` SPA.
- [ARCHITECTURE.md](../ARCHITECTURE.md) — the full system design.
- [Architecture deep-dives](architecture/) — layers, registry, vault, cadence, aggregation.
- [Documentation hub](README.md).
