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
   {framework}/                                  # one per framework run against this vault
      {period_id}/                               # e.g. 2026-Q1
         run_{timestamp}_{run_id8}/              # immutable per-run folder
            ...                                  # see §Per-run folder
      ...
   state/                                        # mutable, NOT under Object Lock
      {framework}/
         policies/
            {policy_id}.json                     # one per-policy state shard
```

> **Not yet implemented.** Earlier drafts placed a vault-level
> `manifest.json` at the root and a regenerable per-period
> `{framework}/{period_id}/summary.json` alongside the run folders.
> Neither is written by the current code — the only manifest is the
> per-run `manifest.json` (schema `run.v1`), and the only summary is the
> per-run `summary.json` inside each run folder. Period state is derived
> on the fly (see §Period state).

The `state/` subtree is structurally separate from the signed
`{framework}/` subtree for exactly one reason: state shards are
**mutable by design** (they update every run), while signed evidence
under `{framework}/` should
live under retention-and-Object-Lock so auditors can trust that
historic envelopes have not been re-signed.

**Loss of `state/` is recoverable.** The next run treats every
policy as first-run and re-evaluates, surfacing a loud
"first-run: N policies will evaluate for the first time" warning.
Evidence integrity is unaffected. The signing scheme does not
depend on state.

See [`10-cadence-model.md`](10-cadence-model.md) §Per-policy state
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

## Vault-level `manifest.json` (planned — not yet implemented)

> **Not yet implemented.** No code writes a vault-level `manifest.json`
> (schema `vault.v1`, `created_by_cli`, `project_id`, `vault_root`).
> Only the per-run manifest (`run.v1`, below) exists today. The design
> intent — a root manifest a future CLI inspects to detect an
> incompatible vault layout and either upgrade in place or refuse to
> write until an explicit migration runs — is retained here as a
> forward-compatibility note, not a shipped artifact.

---

## Per-run folder

```
run_20260215T140000Z_a3f8b2c1/
   manifest.json                     # run identity + file_hashes (schema run.v1)
   summary.json                      # per-run summary (schema summary.v2)
   policies/
      {policy_id}/
         envelopes/
            {evidence_type}__{source_id}[_{catalog_id}].json   # one signed envelope per evidence type
            ...
         result.json                # full PolicyResult (includes violations)
      ...
```

> **Not yet implemented.** Two sub-trees earlier drafts placed here are
> not written by the current pipeline: a per-policy `attachments/`
> folder mirroring merged manual PDFs (the `manual.pdf` plugin hashes
> the merged PDF and discards the bytes — nothing is persisted to the
> vault via `PutBinary`), and a run-level `diagnostics.json`. Do not
> assume either exists when reading a real vault.

### `manifest.json` (per-run)

The shipped `core.Manifest` (`internal/core/manifest.go`, schema
`run.v1`) is deliberately small — just enough to identify the run and
sign every file in the folder. Its fields:

```json
{
  "schema_version":     "run.v1",
  "run_id":             "a3f8b2c1-9d4e-4b23-8f7a-1e5c2d8a9b0f",
  "framework":          "soc2",
  "period_id":          "2026-Q1",
  "started_at":         "2026-02-15T14:00:00Z",
  "completed_at":       "2026-02-15T14:01:42Z",

  "file_hashes": {
    "summary.json":      "sha256:7f3a9c8e...",
    "policies/soc2.cc6.1.mfa_enforced/result.json":
      "sha256:c9d4f2a1...",
    "policies/soc2.cc6.1.mfa_enforced/envelopes/directory_user__aws.iam.json":
      "sha256:e3b0c442..."
  },

  "exceptions_applied": [
    {
      "policy_id":   "soc2.cc6.1.mfa_enforced",
      "resource_id": "iam_user_legacy_svc",
      "state":       "waived",
      "approved_by": "jane.doe@acme.com",
      "expires_at":  "2026-07-15"
    }
  ],

  "signature": {
    "algorithm":  "ed25519",
    "public_key": "MCowBQYDK2VwAyEA1lzN6...",
    "value":      "k7Cv9XmYz0fF..."
  }
}
```

`framework`, `period_id`, and `exceptions_applied` are `omitempty`.
`manifest.json` is the single source of truth for the run's identity
and — via `file_hashes` — the integrity root of every other file in
the run folder. A reader inspecting any single file in the run folder
can find the manifest as a sibling, two directories up if necessary;
the manifest tells them whether that file has been tampered with since
the run was written.

**Not yet implemented.** Earlier drafts of this manifest carried a
dozen extra fields — `framework_version`, `period_start`/`period_end`,
`commit_sha`/`commit_time`, `cli_version`/`cli_commit`,
`evidence_type_versions`, `effective_parameters`,
`policies_planned`/`policies_evaluated`, `ci_environment`, `backfill`.
None of these exist on `core.Manifest` today. Most of that metadata
*does* travel on the cloud `SubmissionPayload`
(see [`06-aggregation.md`](06-aggregation.md)); it is simply not
restated in the on-disk run manifest. Do not assume any of these fields
are present when reading a real vault.

### Run integrity: manifest as signed Merkle root

Only `manifest.json` is signed. Every other file in the run folder is
covered by `manifest.file_hashes`:

- `summary.json`, every `result.json`, and every signed envelope JSON
  is hashed with SHA-256 at write time.
- The hashes are recorded in `manifest.file_hashes`, keyed by path
  relative to the run-folder root.
- The manifest is serialized to canonical JSON (**with the `signature`
  field omitted entirely** — not set to null), signed once with a fresh
  ephemeral Ed25519 keypair, the private key is discarded, and the
  signature is embedded.

This is a single-level Merkle: `manifest.signature` → covers the
entire `file_hashes` table → which covers every file. One signature
verifies the whole run folder. To detect tampering:

```
1. Read manifest.json from the run folder.
2. Verify manifest.signature (with the signature field omitted from the input).
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

### `summary.json` (per-run)

Full-fidelity summary including per-policy violations. This is what
the dashboard reads when the customer is self-hosted; it's also what
auditors look at first. The shipped shape is `core.FrameworkRunSummary`
(`internal/core/summary.go`, schema `summary.v2`): a small top-level
header plus the full `[]PolicyResult`. There is **no** top-level
`totals` or `categories` block — run-level counts are computed by the
aggregator into the cloud `SubmissionPayload`, not persisted here.

```json
{
  "schema_version": "summary.v2",
  "run_id":         "a3f8b2c1-...",
  "framework":      "soc2",
  "period_id":      "2026-Q1",
  "completed_at":   "2026-02-15T14:01:42Z",

  "policies": [
    {
      "PolicyID":           "soc2.cc6.1.mfa_enforced_admins",
      "Controls":           [{ "framework": "soc2", "framework_version": "soc2-2017@1.0.0", "control_id": "SOC2.CC6.1", "relationship": "equal" }],
      "Status":             "fail",
      "Severity":           "high",
      "Category":           "access_control",
      "EffectiveParams":    {},
      "Violations": [
        {
          "ResourceID": "AIDAEXAMPLE01",
          "Reason":     "MFA disabled for alice@acme.com",
          "Details": {
            "evidence_file": "policies/soc2.cc6.1.mfa_enforced_admins/envelopes/directory_user.v2__aws.iam.json"
          }
        },
        { /* ... */ }
      ],
      "ResourcesEvaluated": 47,
      "ResourcesFailed":    3,
      "EvidenceEnvelopes":  ["policies/soc2.cc6.1.mfa_enforced_admins/envelopes/directory_user.v2__aws.iam.json"],
      "RuleVersion":        "rules.mfa_enforced.v1",
      "ConfiguredCadence":  "daily",
      "PolicyContentHash":  "sha256:...",
      "NextDueAt":          "2026-02-16T14:00:00Z"
    },
    /* ... */
  ]
}
```

> **Key casing.** The top-level `FrameworkRunSummary` fields carry
> `json:` tags (snake_case), but `core.PolicyResult` and `core.Violation`
> carry **no** json tags — so each `policies[]` element marshals with Go
> field names (`PolicyID`, `ResourcesEvaluated`, `Violations`, …). The
> nested `Controls` values use `ControlRef`'s own snake_case tags. This
> mixed casing is real; don't "normalize" it in a reader.

### `policies/<policy_id>/result.json`

The persisted `core.PolicyResult` — the same element rendered inside
`summary.json.policies[]` (same Go type, same PascalCase keys),
including its `Violations` and `EvidenceEnvelopes` paths. The summary is
the index; the per-policy result is the detail.

### `policies/<policy_id>/envelopes/`

One signed envelope file **per evidence type** within a (slot, source)
binding (`collector.groupByType` — when a source emits a single accepted
type this is one envelope per (slot, source)). The filename convention is
`{evidence_type}__{source_id}.json`, with a `_{catalog_id}` suffix when
the binding carries a catalog entry (the manual flow always does). For
the manual flow:

```
policies/soc2.cc6.3.access_review_quarterly/envelopes/signed_document__manual.pdf_access_review_quarterly.json
```

> **Not yet implemented.** Earlier drafts mirrored the merged manual PDF
> into a per-policy `attachments/{evidence_id}/` folder as a sibling of
> `envelopes/`. No code writes it — `Vault.PutBinary` is never called on
> the production path; the `manual.pdf` plugin hashes the merged PDF and
> discards the bytes, recording only the hash and the customer-side
> upload URI in the signed record. There is no vault-side PDF sidecar
> today, and therefore no per-policy `attachments/` folder.

> **Not yet implemented.** A run-level `diagnostics.json` (schema
> `diagnostics.v1`, source-level errors / schema-validation events) is
> not written by the current pipeline. Note that a record failing its
> evidence-type schema is **not** silently dropped regardless — the
> first non-conforming record fails the binding and tags the policy
> `error` (see [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md));
> that outcome surfaces in the policy's `result.json`, not a separate
> diagnostics file.

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
      "type":         "directory_user",
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
`file_hashes` table covers every envelope file). For the manual flow,
the `manual.pdf` plugin emits a single `signed_document` record whose
payload is `{evidence_id, period_id, file_present, file_hash,
file_size, uploaded_at, in_temporal_window, file_valid,
validation_failures, expected_uri, source_files}` — where `file_hash`
is the SHA-256 of the merged PDF and `expected_uri` is the customer's
upload **folder** URI (`{scheme}://{bucket}/{prefix}{evidence_id}/{period_id}/`).
The PDF bytes themselves are not persisted to the vault today (see the
"Not yet implemented" attachments note above); the hash inside the
signed record is what an auditor re-checks against the customer's copy.

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
(low-level `Encode`/`Sign`/`Verify`, plus the typed wrappers
`Envelope`/`VerifyEnvelope`/`EncodeEnvelope` and
`Manifest`/`VerifyManifest`/`EncodeManifest`) and reused everywhere —
every envelope, every signature, every verification.

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
2. Extract `signature` block; rebuild the three-field object
   (`format_version`, `produced_at`, `records`) with the `signature`
   field **omitted entirely** (not set to null).
3. Compute canonical JSON of that object.
4. Decode `public_key` (base64 → 32 bytes) and `value` (base64 → 64
   bytes).
5. Call `ed25519.Verify(public_key, canonical_bytes, signature_value)`.
6. If `true`: signature valid.
7. For the manual flow, the `signed_document` record carries a
   `file_hash` (SHA-256 of the merged PDF); an auditor re-checks it by
   hashing their own copy of the evidence and comparing. (The CLI does
   not persist the PDF bytes in the vault today, so there is no
   vault-relative attachment path to hash.)

The reference verifier is implemented in Go in `internal/sign`
(`sign.VerifyEnvelope` for envelopes, `sign.VerifyManifest` for the
run manifest). A browser implementation lives in
`sigcomply-evidence-spa/src/verify/` and uses WebCrypto's `subtle`
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
intentionally does not duplicate. The full list of paid features and
how the submission powers them lives in
[`06-aggregation.md`](06-aggregation.md) §What the paid Rails app does.

> **Not yet implemented.** Earlier designs for this section described a
> regenerable `{framework}/{period_id}/period_state.json` cache and a
> `.closed` period-closure marker (with a `--reopen-period` flag to
> override it). Neither exists in the code today. Period state is
> always derived on the fly by the algorithm above; there is no cache
> file to write and no closure marker to honor.

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
| **CI runner (writer)** | `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` on the vault prefix. **No** `s3:DeleteObject`. | Writes new run folders; reads existing state shards / prior envelopes it must reference (e.g. carry-forward). Append-only is enforced by IAM, not just convention. |
| **`sigcomply report` (auditor read)** | `s3:GetObject`, `s3:ListBucket` on the vault prefix. **No** write or delete. | Reads run folders to produce reports. |
| **Self-hosted dashboard reader** | `s3:GetObject`, `s3:ListBucket` on the vault prefix. | Reads summaries; does not modify. |

Retention and deletion are governed entirely by the customer's
storage-layer lifecycle policies, not by the CLI — see the note under
§Retention.

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

> **Not yet implemented — customer-side responsibility today.** The
> CLI has no lifecycle feature set. It does **not** delete vault data,
> does **not** read a `retention:` config block (none exists in
> `VaultConfig`), does **not** stamp any `retention_floor`,
> `manifest.lifecycle.*`, `legal_hold.json`, or
> `manifest.lifecycle.gdpr_deletions[]` field, and ships no lifecycle
> IaC template. Earlier drafts described all of the above as shipped;
> none of it is in the code.

Retention, deletion, legal hold, and GDPR erasure are entirely the
customer's storage-layer concern in v1, configured directly on the
bucket (S3 lifecycle rules + Object Lock, GCS object lifecycle +
retention/Bucket Lock, Azure Blob immutability). The product position
is unchanged: the vault is the customer's, append-only by storage-layer
policy, and the CLI never deletes from it.

Customer-side guidance worth stating (advice, not a CLI feature):

- SOC 2 typically expects ~7-year evidence retention post-period
  close; encode that as a bucket lifecycle rule, not a CLI setting.
- Because the signing model makes in-place redaction impossible (it
  would invalidate signatures), a GDPR erasure request is satisfied by
  deleting the whole envelope file — the manifest's `file_hashes` entry
  then becomes the cryptographic trace that something used to exist at
  that path. A re-signing migration tool is a possible future
  direction, not a shipped feature.
- Vault objects encrypted at rest with a customer KMS key: disable
  auto-delete on the CMK (loss of the key means loss of the vault), and
  prefer in-place key rotation that preserves access to old objects.
  Ed25519 envelope signatures are independent of storage encryption, so
  key rotation never invalidates a signature.

A richer, opt-in lifecycle layer (retention stamping, legal-hold
markers, a GDPR re-signing tool) may arrive later; until it does, do
not document any of it as available.

---

## Versioning & forward compatibility

The versioned persisted artifacts today:

- per-run `manifest.json` → `run.v1`
- `summary.json` → `summary.v2`
- envelopes → `envelope.v1`
- evidence type payloads → version embedded in the record's `type`
  (e.g. `directory_user.v2`)

`result.json` is the raw `core.PolicyResult` and carries **no** schema
version stamp today. The `vault.v1` and `diagnostics.v1` versions belong
to artifacts that are not yet written (see the "Not yet implemented"
notes above).

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
| Were the recorded policy results computed by the CLI version claimed? | Partial (modulo trust in the binary's release artifact) | The on-disk run manifest does not record the CLI version today; the CLI version travels on the cloud `SubmissionPayload` (`cli_version`) instead. Re-derivation relies on the released binary's commit SHA. |
| Did the evidence in this envelope match what the source actually returned? | Strong yes — for state in the source at `collected_at` | Re-run the same plugin against the same source with frozen credentials; compare records. (Time-sensitive sources may have drifted.) |
| Has this envelope been modified since it was written? | Strong no | Verify the envelope's Ed25519 signature offline. |
| Has the manual evidence PDF been substituted? | Strong no | Verify SHA-256 of the customer's PDF matches the `file_hash` inside the signed `signed_document` record. (The CLI does not persist the PDF bytes in the vault; the hash lives in the signed envelope.) |
| Has `result.json` / `summary.json` been modified since the run was written? | Strong no | Verify `manifest.signature`; recompute SHA-256 of each file and compare to `manifest.file_hashes`. Any mismatch is tampering. |
| Has an envelope been replaced with a valid envelope from a different run? | Strong no | Each envelope's path is hashed in `manifest.file_hashes`. Substituting a different envelope file at the same path changes the hash; the manifest signature fails. |
| Did the customer fabricate evidence by running the CLI against a fake source? | Out of scope. | The CLI does not attest to source authenticity. Fabricating evidence is fraud; no compliance tool prevents it. |

The signing model is about preserving integrity, not preventing fraud.
That distinction is fundamental and shipped explicitly in any auditor-
facing material.
