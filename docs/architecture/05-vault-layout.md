# 05 — Vault Layout

The vault is the customer's source of truth for evidence. Every signed
envelope, every policy result, every run summary lands here. This
document specifies the directory layout, the envelope format, the
signing algorithm, and the rules that make a vault written in 2026
readable by an auditor in 2031.

---

## Top-level layout

```
{vault_root}/
   manifest.json                                 # vault-level metadata
   {framework}/                                  # one per framework run against this vault
      {period_id}/                               # e.g. 2026-Q1
         run_{timestamp}_{run_id8}/              # immutable per-run folder
            ...                                  # see §Per-run folder
         summary.json                            # rebuilt every run in this period
         .closed                                 # optional marker: period closed by auditor
      ...
   state/                                        # mutable, NOT under Object Lock
      {framework}/
         policies/
            {policy_id}.json                     # one per-policy state shard
```

The `state/` subtree is structurally separate from `evidence/` for
exactly one reason: state shards are **mutable by design** (they
update every run), while signed evidence under `{framework}/` should
live under retention-and-Object-Lock so auditors can trust that
historic envelopes have not been re-signed.

**Loss of `state/` is recoverable.** The next run treats every
policy as first-run and re-evaluates, surfacing a loud
"first-run: N policies will evaluate for the first time" warning.
Evidence integrity is unaffected. The signing scheme does not
depend on state.

See [`11-cadence-model.md`](11-cadence-model.md) §Per-policy state
shards for the shard schema, the monotonic write rule, and the
recovery story.

- **vault_root** is the location configured in `.sigcomply.yaml`
  (`s3://acme-evidence/sigcomply/`, `/var/sigcomply/vault/`,
  `gs://acme-evidence/`, etc.).
- **framework** is the framework ID for that run (`soc2`,
  `iso27001`). Each framework lives in its own subtree; framework runs
  never interleave at the file level.
- **period_id** is the period stamp computed at run time
  (`2026-Q1`, `FY2026`, custom). Path encodes membership; metadata in
  each run folder is the authoritative period reference.
- **run folder name** is `run_{YYYYMMDDTHHMMSSZ}_{first8charsofrunid}`,
  ISO 8601 basic UTC, colon-free for S3-compatible-tool friendliness.

The vault is **append-only at the run level**: a run folder is
written once during a single CLI invocation and never modified
afterward. There is no edit, delete, or merge operation that mutates
existing run folders.

---

## Vault-level `manifest.json`

Written by the first run; subsequent runs read it to verify
compatibility, never overwrite it.

```json
{
  "schema_version": "vault.v1",
  "created_at":     "2026-01-15T09:00:00Z",
  "created_by_cli": "sigcomply 1.0.0",
  "project_id":     "acme",
  "vault_root":     "s3://acme-evidence/sigcomply/"
}
```

If a future CLI version introduces an incompatible vault layout, it
will inspect this file and either upgrade in place (writing a new
`schema_version` field) or refuse to write until the operator runs
an explicit migration command.

---

## Per-run folder

```
run_20260215T140000Z_a3f8b2c1/
   manifest.json                     # run identity, versions, env
   summary.json                      # full-fidelity run summary
   policies/
      {policy_id}/
         envelopes/
            {evidence_type}__{source_id}.json   # one signed envelope per (slot, source)
            ...
         attachments/                # binary files referenced by envelopes
            {evidence_id}/
               evidence.pdf
            ...
         result.json                # full PolicyResult (includes violations)
      ...
   diagnostics.json                 # source-level errors, schema validation drops
```

### `manifest.json` (per-run)

```json
{
  "schema_version": "run.v1",

  "run_id":          "a3f8b2c1-9d4e-4b23-8f7a-1e5c2d8a9b0f",
  "framework":       "soc2",
  "framework_version": "soc2-2017@1.2.0",
  "period_id":       "2026-Q1",
  "period_start":    "2026-01-01T00:00:00Z",
  "period_end":      "2026-03-31T23:59:59Z",

  "commit_sha":      "f3e8d7c6b5a4...",
  "commit_time":     "2026-02-15T13:55:00Z",

  "started_at":      "2026-02-15T14:00:00Z",
  "completed_at":    "2026-02-15T14:01:42Z",

  "cli_version":     "1.0.0",
  "cli_commit":      "f3e8d7c6...",

  "evidence_type_versions": {
    "user_record":      1,
    "iam_role":         1,
    "signed_document":  1,
    "s3_bucket":        1
  },

  "effective_parameters": {
    "soc2.cc6.1.access_key_rotation": { "max_age_days": 60 },
    "soc2.cc6.1.inactive_users":      { "inactive_days": 30 }
  },

  "policies_planned": 412,
  "policies_evaluated": 412,
  "exceptions_applied": [
    {
      "policy_id":      "soc2.cc6.1.mfa_enforced",
      "scope":          { "resource_id": "iam_user_legacy_svc" },
      "state":          "waived",
      "approved_by":    "jane.doe@acme.com",
      "expires_at":     "2026-07-15"
    }
  ],

  "ci_environment": {
    "provider":   "github",
    "repository": "acme/infrastructure",
    "branch":     "main",
    "workflow":   "compliance.yml",
    "run_url":    "https://github.com/acme/infrastructure/actions/runs/1234"
  },

  "backfill": false,

  "file_hashes": {
    "summary.json":      "sha256:7f3a9c8e...",
    "diagnostics.json":  "sha256:b2e15d4a...",
    "policies/soc2.cc6.1.mfa_enforced/result.json":
      "sha256:c9d4f2a1...",
    "policies/soc2.cc6.1.mfa_enforced/envelopes/user_record__aws.iam.json":
      "sha256:e3b0c442...",
    "policies/soc2.cc6.1.access_review/attachments/access_review_quarterly/evidence.pdf":
      "sha256:194523ba..."
  },

  "signature": {
    "algorithm":  "ed25519",
    "public_key": "MCowBQYDK2VwAyEA1lzN6...",
    "value":      "k7Cv9XmYz0fF..."
  }
}
```

`manifest.json` is the single source of truth for the run's identity,
the versions that were in play, and — via `file_hashes` — the integrity
root of every other file in the run folder. A reader inspecting any
single file in the run folder can find the manifest as a sibling, two
directories up if necessary; the manifest tells them whether that file
has been tampered with since the run was written.

### Run integrity: manifest as signed Merkle root

Only `manifest.json` is signed. Every other file in the run folder is
covered by `manifest.file_hashes`:

- `summary.json`, `diagnostics.json`, every `result.json`, every
  signed envelope JSON, and every attachment binary (PDFs) is hashed
  with SHA-256 at write time.
- The hashes are recorded in `manifest.file_hashes`, keyed by path
  relative to the run-folder root.
- The manifest is serialized to canonical JSON (with `signature: null`),
  signed once with a fresh ephemeral Ed25519 keypair, the private key
  is discarded, and the signature is embedded.

This is a single-level Merkle: `manifest.signature` → covers the
entire `file_hashes` table → which covers every file. One signature
verifies the whole run folder. To detect tampering:

```
1. Read manifest.json from the run folder.
2. Verify manifest.signature (with signature set to null in the input).
3. For each entry in file_hashes:
     compute SHA-256 of the file at the relative path
     compare to the recorded hash
   If any mismatch: a file has been modified post-write.
4. (Optional) For each envelope file: also verify its own internal
   signature, which is a defense in depth — an attacker would need to
   forge both the envelope's signature and the manifest's signature to
   tamper with an envelope.
```

**Why two layers of signing?** Each envelope carries its own
ephemeral-keypair signature so it remains independently verifiable in
isolation (an auditor handed a single envelope file with no other
state can still verify it). The manifest's signature additionally binds
the *set* of envelopes to the run — preventing an attacker from
substituting a valid envelope from a different run.

**What about result.json and summary.json?** They are unsigned but
hashed by the manifest. Modifying `summary.json` to flip a count
breaks the manifest's recorded hash, and the manifest's signature
makes that mismatch evidence of tampering.

**What about the optional period_state.json cache?** Caches are
intentionally regenerable and not signed; readers regenerate them from
the immutable per-run folders if they need to trust the contents.

### `summary.json` (per-run)

Full-fidelity summary including per-policy violations. This is what
the dashboard reads when the customer is self-hosted; it's also what
auditors look at first.

```json
{
  "schema_version": "summary.v1",
  "run_id":         "a3f8b2c1-...",
  "framework":      "soc2",
  "period_id":      "2026-Q1",

  "totals": {
    "policies_total":    412,
    "policies_passed":   395,
    "policies_failed":   8,
    "policies_skipped":  6,
    "policies_error":    3,
    "policies_na":       0,
    "policies_waived":   0,
    "compliance_score":  0.964
  },

  "categories": {
    "access_control":   { "passed": 89, "failed": 3, ... },
    "encryption":       { "passed": 41, "failed": 0, ... },
    ...
  },

  "policies": [
    {
      "policy_id":          "soc2.cc6.1.mfa_enforced",
      "control_id":         "SOC2.CC6.1",
      "status":             "fail",
      "severity":           "high",
      "category":           "access_control",
      "resources_evaluated": 47,
      "resources_failed":    3,
      "violations": [
        {
          "resource_id": "AIDAEXAMPLE01",
          "reason":      "MFA disabled for alice@acme.com",
          "details": {
            "evidence_file": "policies/soc2.cc6.1.mfa_enforced/envelopes/user_record__aws.iam.json"
          }
        },
        { /* ... */ }
      ],
      "rule_version":       "rules.mfa_enforced.v1",
      "effective_params":   {}
    },
    /* ... */
  ]
}
```

### `policies/<policy_id>/result.json`

Same shape as one element of `summary.json.policies`, but more
verbose (includes diagnostics and the full list of envelope file
paths). The summary is the index; the per-policy result is the
detail.

### `policies/<policy_id>/envelopes/`

One signed envelope file per (slot, source) pair. The filename
convention is `{evidence_type}__{source_id}.json` with a double
underscore to make the source-vs-type boundary unambiguous. For the
manual flow:

```
policies/soc2.cc6.1.access_review/envelopes/signed_document__manual.pdf.json
policies/soc2.cc6.1.access_review/attachments/access_review_quarterly/evidence.pdf
```

The envelope's manifest references the PDF by relative path; the PDF
mirror is a sibling.

### `policies/<policy_id>/attachments/`

Binary attachments referenced by envelopes (currently: manual evidence
PDFs). Mirroring policy:

- One PDF per `(evidence_id, period)` combination.
- The same PDF is mirrored under every policy folder whose envelope
  references it. Auditors verify each policy folder independently;
  duplicating bytes is the cost of self-containment.

### `diagnostics.json`

Non-fatal events surfaced during the run: schema validation drops,
partial collector failures, plugin warnings. Distinct from policy
results so auditors can see what the CLI noticed but didn't act on.

```json
{
  "schema_version": "diagnostics.v1",
  "events": [
    {
      "level":     "warn",
      "source_id": "aws.iam",
      "kind":      "schema_validation",
      "message":   "Record id=AIDA... missing required field 'mfa_enabled'; dropped.",
      "context":   { "evidence_type": "user_record" }
    }
  ]
}
```

---

## Envelope format

The envelope is the unit of verification. One file, one signature,
one fresh keypair.

### Canonical structure

```json
{
  "format_version": "envelope.v1",
  "produced_at":    "2026-02-15T14:00:42Z",

  "records": [
    {
      "type":         "user_record",
      "id":           "AIDAEXAMPLE01",
      "source_id":    "aws.iam",
      "collected_at": "2026-02-15T14:00:01Z",
      "payload": {
        "id":           "AIDAEXAMPLE01",
        "email":        "alice@acme.com",
        "mfa_enabled":  false,
        "last_used_at": "2026-02-12T09:14:00Z",
        "is_admin":     true
      }
    },
    /* ... */
  ],

  "signature": {
    "algorithm":  "ed25519",
    "public_key": "MCowBQYDK2VwAyEA1lzN6...",
    "value":      "j8Bk0EYmGFh2..."
  }
}
```

The envelope has four fields — `format_version`, `produced_at`,
`records`, `signature`. Context that earlier drafts carried inside the
envelope (policy_id, slot, evidence_type, source_id, run_id) is
expressed structurally: it lives in the envelope's file path
(`policies/{policy_id}/envelopes/{evidence_type}__{source_id}.json`)
and is bound to the run by the per-run `manifest.json` (whose
`file_hashes` table covers every envelope file). Attachments are
referenced by the relevant record's payload — for example, the
`manual.pdf` plugin emits a record whose payload is `{evidence_id,
file_hash, file_path, period, framework}`, and the PDF itself is
mirrored at the referenced path and hashed in the run manifest.

### Signed payload

The signature covers the **canonical JSON serialization** of the
envelope's three content fields, in this exact shape:

```
canonical_json({
  format_version: ...,
  produced_at:    ...,
  records:        [...]
})
```

The signature field is not part of the signed payload; a verifier
reconstructs the three-field object from the parsed envelope.

**Canonical JSON rules** (RFC 8785-style, sufficient subset):

1. UTF-8 encoding
2. No insignificant whitespace
3. Object keys sorted lexicographically
4. Strings escaped per RFC 8259, using `\u` escapes only for control
   characters
5. Numbers in shortest unambiguous form; floats use shortest
   round-trippable decimal
6. Arrays preserve their existing order

The signing function is implemented once in `internal/sign`
(`Encode`, `Sign`, `Verify`, plus the envelope and manifest wrappers)
and reused everywhere — every envelope, every signature, every
verification.

### Signing algorithm

1. Generate fresh Ed25519 keypair (32-byte seed from system CSPRNG).
2. Serialize the envelope (minus signature) to canonical JSON.
3. Sign the canonical bytes with Ed25519, producing a 64-byte
   signature.
4. Encode public key (32 bytes) and signature (64 bytes) as base64.
5. Inject `signature` into the envelope.
6. **Discard the private key immediately** (`for i := range priv {
   priv[i] = 0 }`). It exists in memory only between steps 1 and 3.

The keypair is per-envelope, not per-run. A run writing 500 envelopes
generates 500 keypairs. This is the threat model: an attacker who
compromises the CLI process *during* a run can only forge the
envelopes signed *during* that run; they cannot forge prior or
subsequent envelopes because those private keys never existed in
their reachable memory.

### Verification (offline, auditor side)

Given a single envelope file, no other state:

1. Parse JSON.
2. Extract `signature` block; clone the envelope with `signature: null`.
3. Compute canonical JSON of the cloned envelope.
4. Decode `public_key` (base64 → 32 bytes) and `value` (base64 → 64
   bytes).
5. Call `ed25519.Verify(public_key, canonical_bytes, signature_value)`.
6. If `true`: signature valid. Move on to attachment integrity.
7. For each entry in `attachments`, compute SHA-256 of the file at
   the relative path; compare to the recorded hash.

A reference verifier is implemented in Go in
`internal/core/attestation/verify.go`. A browser implementation lives
in `sigcomply-evidence-spa/src/verify/` and uses WebCrypto's `subtle`
Ed25519 API — no Node, no CLI required, runs in a static page.

---

## Period state — derived, not stored authoritatively

Recall from `01-conceptual-model.md`: period state is the latest-wins
roll-up across all runs in a period. It is **never stored as an
authoritative mutable file**. Readers (the dashboard, `sigcomply
report`, an auditor with `find` and `jq`) derive it by:

1. List `{framework}/{period_id}/run_*/`.
2. For each policy_id appearing across runs, take the result from the
   run with the latest `completed_at` that produced a result for that
   policy.
3. Combine with `summary.json.policies[i]` from that run.

That's the algorithm. It runs in `O(runs × policies)`, which at
typical audit volumes (one run a day, 400 policies, one quarter = 90
runs) is `36,000` comparisons — trivial.

### Throughout-period evidence: what the vault preserves, what analyzes it

SOC 2 Type II auditors test whether a control "operated effectively
*throughout*" the period — not just at the end. Latest-wins alone
hides the case where a policy was failing for 30 days mid-period
before being remediated.

**The vault preserves the data needed to reason about throughout-period
behavior**: every run folder is immutable, so the per-day or per-run
state of every policy is recoverable forever. A reader walking
`{framework}/{period_id}/run_*/policies/<P>/result.json` in chronological
order has the full timeline.

**The free CLI does not ship an analyzer for this.** `sigcomply report`
produces only snapshot views (latest, exceptions, integrity) — it
does not compute deviation timelines, drift, or continuous-monitoring
narratives.

**Time-series analysis is the paid SigComply Cloud / Rails app's job.**
The Rails app receives aggregated counts per run via the
`SubmissionPayload` (see [`06-aggregation.md`](06-aggregation.md)),
stores them in its DB over time, and uses that accumulated history to
generate:

- Deviation timelines per policy (pass/fail windows, time-in-violation)
- Drift detection across periods (Q1 2026 vs Q1 2025)
- Continuous-monitoring alerts as state changes
- Auditor-ready Type II reports that combine latest-state, deviation
  timelines, and exception register into a single deliverable

A customer who needs the throughout-period narrative either subscribes
to SigComply Cloud, self-hosts the Rails app (if offered as an
option), or writes their own analytics against the vault. The vault
format guarantees that whichever path they choose, the underlying data
is structurally identical: a sequence of immutable run folders, each
with signed integrity guarantees.

| Question | Where it's answered |
|---|---|
| "What's the state of control X at period close?" | Free CLI: `sigcomply report --view latest`. Vault-readable. |
| "What was waived during the period?" | Free CLI: `sigcomply report --view exceptions`. Vault-readable. |
| "Has any evidence been tampered with?" | Free CLI: `sigcomply report --view integrity`. Vault-readable. |
| "Did control X operate effectively *throughout* the period?" | **Paid Rails app.** Computes deviation timeline from accumulated per-run submissions. |
| "Has compliance posture drifted year-over-year?" | **Paid Rails app.** Cross-period analytics. |
| "Alert me when MFA enforcement state changes." | **Paid Rails app.** Continuous-monitoring alerts. |

The vault is the data layer for both free and paid tooling; the paid
analytical layer adds longitudinal capabilities the free CLI
intentionally does not duplicate.

### Optional cache

For very busy projects, the dashboard or `sigcomply report` *may*
materialize a cache at `{framework}/{period_id}/period_state.json`.
The cache is:

- A roll-up of `summary.json.policies` for the period
- Marked `"cache": true` and stamped with the latest `run_id`
  contributing to it
- **Always regenerable** from the run folders; never authoritative

The CLI itself does not write this cache. Cache invalidation is the
reader's concern.

### Period closure

When auditing is complete for a period, an auditor (or operator) may
drop a marker file:

```
{framework}/{period_id}/.closed

# Contents:
{
  "schema_version": "period_closure.v1",
  "closed_at":      "2026-04-15T17:00:00Z",
  "closed_by":      "jane.doe@acme.com",
  "auditor":        "Acme Audit LLC",
  "reason":         "Q1 2026 SOC 2 fieldwork complete."
}
```

Subsequent runs detect the marker and refuse to write to that period
unless `--reopen-period` is explicitly passed. This is soft
enforcement: the file is data, not policy; deleting it removes the
protection. But the marker survives in git history if it's committed,
and in vault snapshots if backups exist.

---

## Backend abstraction

All vault operations go through the `Vault` interface (L1). Vault
backends are **Axis B** of the three plugin axes (see
[`00-three-plugin-axes.md`](00-three-plugin-axes.md) §Axis B):
self-registering factories, blank-import bootstrap, fully
substitutable. The four shipped backends in `internal/vault/` are
just the in-tree set; third parties add their own from
`.sigcomply/plugins/` (see
[`07-extensibility.md`](07-extensibility.md) §Custom vault backends).

| Backend | Identifier | Config requirements |
|---|---|---|
| Local filesystem | `local` | `path` |
| AWS S3 | `s3` | `bucket`, `region`, optional `endpoint`, `force_path_style`, `prefix` |
| GCS | `gcs` | `bucket`, optional `prefix` |
| Azure Blob | `azure_blob` | `account`, `container`, optional `prefix` |
| On-prem S3-compatible | `s3` with `endpoint` + `force_path_style: true` | (MinIO, Ceph, etc.) |
| Custom (third-party) | any registered ID (e.g. `acme.nfs`, `acme.sftp_vault`) | backend-specific; read from `spec.VaultConfig` |

Backend selection is per-project in `.sigcomply.yaml`. The same
backend serves the entire vault — no per-framework override for the
*evidence* vault. (Per-framework override for the *manual upload*
location is separate: that's the `manual.pdf` plugin's `bucket`
config, not the vault — and is itself **Axis A** of the three plugin
axes, with its own self-registering reader registry.)

---

## Vault permissions model

The vault is customer-owned. Different actors need different
permissions. The minimum-privilege model:

| Actor | Permissions | Why |
|---|---|---|
| **CI runner (writer)** | `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` on the vault prefix. **No** `s3:DeleteObject`. | Writes new run folders. Reads only existing data to verify the vault-level `manifest.json` once at startup. Append-only is enforced by IAM, not just convention. |
| **`sigcomply report` (auditor read)** | `s3:GetObject`, `s3:ListBucket` on the vault prefix. **No** write or delete. | Reads run folders to produce reports. |
| **Self-hosted dashboard reader** | `s3:GetObject`, `s3:ListBucket` on the vault prefix. | Reads summaries; does not modify. |
| **Operator (incident response)** | Full read; conditional write only for `.closed` markers and `manifest.lifecycle.legal_hold`. | Documented rare action; logged. |
| **Lifecycle automation** | Conditional `s3:DeleteObject` only on objects older than `retention_days` and *not* under a `legal_hold`. See §Lifecycle. | Implements retention. |

For S3, the CI runner role is typically assumed via OIDC from the
CI provider (no long-lived keys). The shipped GitHub Actions workflow
template (`sigcomply init-ci --ci github`) wires up
`aws-actions/configure-aws-credentials` with `role-to-assume`. The
trust policy on the AWS role pins the GitHub OIDC issuer + the repo
name; only that repo's CI can assume it.

Equivalent guidance for GCS uses Workload Identity Federation; for
Azure Blob, federated credentials.

**Do not co-locate the CI role with broader infrastructure write
access.** A bug in a plugin or rule should not be able to delete the
vault. The role assumed by the CLI for vault writes must scope only
to the vault prefix.

---

## Lifecycle: retention, deletion, legal hold

The vault is append-only at the run-folder level *during the
retention window*. After the window expires, deletion is permitted
under controlled rules.

### Retention

SOC 2 typically requires 7-year evidence retention post-period close;
ISO 27001 varies. Set retention at the bucket level:

```yaml
# .sigcomply.yaml (excerpt)
vault:
  backend: s3
  bucket:  acme-evidence
  region:  us-east-1
  retention:
    minimum_years: 7        # no deletion before this many years post-period close
    auto_delete:   false    # if true, lifecycle automation may delete past this
```

The CLI does **not** delete vault data. Deletion is performed by
the customer's bucket lifecycle policies (S3 lifecycle rules, GCS
object lifecycle, Azure Blob lifecycle). The CLI's role is to stamp
`retention_floor` into each run's `manifest.json` (computed as
`completed_at + minimum_years`) so external lifecycle automation can
key off it.

A run's `manifest.lifecycle.retention_floor` is the earliest
permitted deletion date. Lifecycle policies must respect it. A
documented sample S3 lifecycle policy is shipped with `sigcomply
init-ci`.

### Legal hold

A run can be marked under legal hold to suspend deletion regardless
of retention floor:

```
{framework}/{period_id}/run_.../legal_hold.json

{
  "schema_version": "legal_hold.v1",
  "asserted_at": "2026-08-15T10:00:00Z",
  "asserted_by": "general.counsel@acme.com",
  "reason":      "Active matter; do not delete pending counsel review.",
  "released_at": null
}
```

Lifecycle policies must check for `legal_hold.json` in every run
folder before deleting. The shipped lifecycle policy template includes
this guard.

### GDPR / personal data deletion

A customer subject to a GDPR erasure request may need to redact a
former employee's email from past evidence. The signing model makes
in-place redaction impossible (it would invalidate signatures).
Approaches:

- **Sealed-envelope deletion**: delete the entire envelope containing
  the identifier. The manifest signature still verifies for the rest
  of the run; the deleted envelope's hash entry in `file_hashes`
  becomes the cryptographic trace that *something* used to be at that
  path. Document the deletion in `manifest.lifecycle.gdpr_deletions[]`.
- **Re-signing migration tool** (planned, v2): produces a new
  envelope set with the identifier replaced, then archives the
  originals to a sealed bucket under separate access controls.

For v1, the only supported response to a GDPR erasure request is
sealed-envelope deletion. Customers anticipating significant GDPR
exposure should plan for this.

### KMS key rotation

Vault objects are encrypted at rest with the customer's KMS key. The
Ed25519 envelope signatures are independent of storage encryption, so
KMS key rotation does not invalidate signatures — but it does affect
whether old envelopes remain *readable*.

**Required**: customers MUST disable KMS auto-delete on the CMK used
for the vault. Loss of the CMK means total loss of the vault. The
shipped IaC templates set `EnableKeyRotation: true` (which rotates
the key material annually within the same key ID, preserving access
to old objects) and explicitly do not destroy old key versions.

For multi-region replication, the replica must be encrypted with a
KMS key in the replica region; cross-region key sharing is a
customer decision.

---

## Versioning & forward compatibility

Every persisted artifact in the vault carries an explicit schema
version:

- `manifest.json` → `vault.v1`, `run.v1`
- `summary.json` → `summary.v1`
- `result.json` → `policy_result.v1`
- envelopes → `envelope.v1`
- diagnostics → `diagnostics.v1`
- evidence type payloads → version embedded in the record
- closure marker → `period_closure.v1`

Forward-compatibility rules:

1. Adding optional fields → same major version.
2. Renaming / changing the meaning of a field → new major version.
3. Removing a field → new major version (existing readers may panic if
   they expected it).
4. A reader encountering an *unknown* major version should refuse to
   interpret the file rather than guess.

A vault written by `sigcomply 1.0.0` in 2026 is readable by every
1.x version forever. A 2.0 release may introduce `envelope.v2`; the
CLI emits the new version going forward, the reference verifier
reads both.

---

## Auditor checklist (what's verifiable, what isn't)

| Question | Answer | How |
|---|---|---|
| Were the recorded policy results computed by the CLI version claimed? | Yes (modulo trust in the binary's release artifact) | `manifest.cli_version` + `cli_commit` cross-referenced with the released binary's commit SHA. |
| Did the evidence in this envelope match what the source actually returned? | Strong yes — for state in the source at `collected_at` | Re-run the same plugin against the same source with frozen credentials; compare records. (Time-sensitive sources may have drifted.) |
| Has this envelope been modified since it was written? | Strong no | Verify the envelope's Ed25519 signature offline. |
| Has the PDF mirrored alongside this envelope been substituted? | Strong no | Verify SHA-256 of the PDF matches the envelope's `attachments[i].sha256`. |
| Has `result.json` / `summary.json` / `diagnostics.json` been modified since the run was written? | Strong no | Verify `manifest.signature`; recompute SHA-256 of each file and compare to `manifest.file_hashes`. Any mismatch is tampering. |
| Has an envelope been replaced with a valid envelope from a different run? | Strong no | Each envelope's path is hashed in `manifest.file_hashes`. Substituting a different envelope file at the same path changes the hash; the manifest signature fails. |
| Did the customer fabricate evidence by running the CLI against a fake source? | Out of scope. | The CLI does not attest to source authenticity. Fabricating evidence is fraud; no compliance tool prevents it. |

The signing model is about preserving integrity, not preventing fraud.
That distinction is fundamental and shipped explicitly in any auditor-
facing material.
