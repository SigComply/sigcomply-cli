# 05: Vault layout

The vault is customer-owned storage that holds every signed envelope, policy result and run
summary. This page owns the directory layout, the persisted file shapes and the signing and
verification procedure. The threat model (what the signatures detect and what they do not) is
owned by [`SECURITY.md`](../../SECURITY.md) §Threat model.

## Not built

None of these is written by the code. Don't assume one exists when reading a vault.

- A vault-level `manifest.json` or a per-period `summary.json`, `period_state.json` or
  `.closed` marker. Period state is derived on read (see [Period state](#period-state)).
- A copy of the original manual uploads. They stay in the customer's upload bucket; only the
  merged PDF is stored (see [Attachments](#attachments)).
- A run-level `diagnostics.json`.
- Any lifecycle feature: retention, deletion, legal hold, GDPR erasure. These are the customer's
  storage-layer settings. The CLI never deletes from the vault.

## Layout

```
{vault_root}/
  {framework}/                     # soc2, iso27001
    {period_id}/                   # the run's period: 2026-Q1, FY2026, custom
      run_{YYYYMMDDTHHMMSSZ}_{run_id[:8]}/
        manifest.json              # run.v1, signed
        summary.json               # summary.v2
        policies/{policy_id}/
          result.json              # core.PolicyResult
          envelopes/{evidence_type}__{source_id}[_{catalog_id}].json   # envelope.v1, signed
          attachments/{evidence_catalog_id}[.{member_id}].pdf          # merged manual PDF
  state/{framework}/policies/{policy_id}.json                          # mutable cadence state
```

- `orchestrator.buildRunRoot` builds the run folder name: ISO 8601 basic UTC (no colons, for
  S3-compatible tools) plus the first 8 characters of the run ID.
- The `{period_id}` in a vault path is always the run's period. A manual entry's own cadence
  window appears only inside its `signed_document` record; see
  [`10-cadence-model.md`](10-cadence-model.md) §Manual evidence periods.
- A run folder is written once, during one CLI invocation, and never modified.
- `state/` is separate because state shards change every run and are never signed. Keep
  `{framework}/` under write-once retention and leave `state/` outside it. If `state/` is lost,
  the next `--scheduled` run treats every policy as first-run and logs
  `first-run: no cadence state found in the vault, so all N due policies evaluate this run`. Shard schema and write
  rules: [`10-cadence-model.md`](10-cadence-model.md) §Per-policy state shards.

### Write failures

A failed envelope or attachment write fails that binding: the collector returns an error and the
policy is tagged `error`. A failed write of `result.json`, `summary.json` or `manifest.json` stops
the run with an execution error, exit 2 (`persistResults`, `writeManifest` in
`internal/orchestrator/orchestrator.go`); nothing is submitted. `recordingVault` lists only writes
that succeeded, so the manifest never vouches for a file that is not there.

## Per-run manifest

`core.Manifest` (`internal/core/manifest.go`, schema `run.v1`):

```json
{
  "schema_version": "run.v1",
  "run_id": "a3f8b2c1-9d4e-4b23-8f7a-1e5c2d8a9b0f",
  "framework": "soc2",
  "period_id": "2026-Q1",
  "started_at": "2026-02-15T14:00:00Z",
  "completed_at": "2026-02-15T14:01:42Z",
  "file_hashes": {
    "summary.json": "sha256:7f3a9c8e...",
    "policies/soc2.cc6.1.mfa_enforced_all_users/result.json": "sha256:c9d4f2a1...",
    "policies/soc2.cc6.1.mfa_enforced_all_users/envelopes/directory_user__aws.iam.json": "sha256:e3b0c442..."
  },
  "exceptions_applied": [
    {
      "policy_id": "soc2.cc6.1.mfa_enforced_all_users",
      "state": "waived",
      "reason": "Legacy service account, decommission tracked in OPS-412",
      "approved_by": "security-lead",
      "expires_at": "2026-07-15",
      "resource_id": "iam_user_legacy_svc"
    }
  ],
  "signature": {
    "algorithm": "ed25519",
    "public_key": "<base64 of the raw 32-byte key>",
    "value": "<base64 of the 64-byte signature>"
  }
}
```

- `framework`, `period_id` and `exceptions_applied` are `omitempty`.
- `AppliedException` also carries `approved_at` and `resource_pattern`.
- `file_hashes` covers every file the run wrote except the manifest itself, keyed by path
  relative to the run folder. `recordingVault` hashes each write.
- The manifest carries no CLI version, commit or parameters. `cli_version` travels on the cloud
  payload ([`06-aggregation.md`](06-aggregation.md)); effective parameters are in `result.json`.

## summary.json and result.json

`core.FrameworkRunSummary` (`internal/core/summary.go`, schema `summary.v2`) has a header
(`schema_version`, `run_id`, `framework`, `period_id`, `completed_at`), `policies` (the full
`[]core.PolicyResult`, violations included) and `scope` (`*scope.Report`, written only when
`experimental.scope` is declared). There are no run totals; the aggregator computes those for
the cloud payload only.

`policies/<policy_id>/result.json` is the same `core.PolicyResult` on its own.

`core.PolicyResult` and `core.Violation` have no JSON tags, so each policy marshals with Go field
names (`PolicyID`, `ResourcesEvaluated`, `Violations`, `EvidenceEnvelopes`), while nested
`Controls` use `ControlRef`'s snake_case tags (`"control_id": "CC6.1"`). Readers must handle the
mixed casing; don't normalize it.

`core.PeriodAggregate` is defined but nothing populates it.

## Envelopes

The collector writes one envelope per evidence type within a (slot, source) binding
(`collector.groupByType`). The path is `envelopes/{evidence_type}__{source_id}.json`, with a
`_{catalog_id}` suffix when the binding has a catalog entry, which every manual binding does:

```
policies/soc2.cc6.3.access_review_quarterly/envelopes/signed_document__manual.pdf_access_review_quarterly.json
```

A fan-out manual entry is still one binding, one record and one envelope; the record carries
every member's verdict.

## Attachments

A record can carry binary `Attachments` (`core.Attachment`, never serialized into the envelope).
The collector writes each one with `PutBinary` to `policies/{policy_id}/attachments/{name}`, after
the record's envelope, so the manifest's `file_hashes` lists it. Names must be a single path
segment (`collector.safeAttachmentName`); a failed write errors the policy.

Today the only attachment is the merged manual PDF:

```
policies/soc2.cc6.3.access_review_quarterly/attachments/access_review_quarterly.pdf
policies/soc2.cc9.2.vendor_assurance/attachments/vendor_assurance.acme_cloud.pdf   # fan-out member
```

The name is the upload folder's ID plus `.pdf`: `{evidence_catalog_id}.pdf`, or
`{evidence_catalog_id}.{member_id}.pdf` for a fan-out member. Its SHA-256 equals the record's
`file_hash` (fan-out: the member's `instances[].file_hash`). A folder with nothing merged (empty,
only unsupported files, or a failed merge) writes no PDF. An exempt fan-out member writes none.

`core.Envelope` has four fields:

```json
{
  "format_version": "envelope.v1",
  "produced_at": "2026-02-15T14:00:00Z",
  "records": [
    {
      "type": "directory_user",
      "id": "AIDAEXAMPLE01",
      "source_id": "aws.iam",
      "collected_at": "2026-02-15T14:00:01Z",
      "payload": { "id": "AIDAEXAMPLE01", "mfa_enabled": false, "is_admin": true }
    }
  ],
  "signature": { "algorithm": "ed25519", "public_key": "<base64>", "value": "<base64>" }
}
```

- `produced_at` is the run's reference time, set once per run so a re-run is byte-identical. It
  precedes the `collected_at` of every record inside. The as-of time of an observation is its
  record's `collected_at`.
- Policy ID, evidence type and source ID are not inside the envelope. They are in its path, and
  the manifest binds the path to the run.
- A manual binding emits one `signed_document` record (`manualManifest` in
  `internal/sources/manual/manual.go`). Its payload has `evidence_id`, `period_id`,
  `file_present`, `file_hash`, `file_size`, `uploaded_at`, `in_temporal_window`, `file_valid`,
  `validation_failures`, `expected_uri` (the upload folder) and `source_files` (per-file name and
  SHA-256 of the original bytes). The merged PDF is stored beside it under `attachments/`
  (below); the full manual-evidence contract is in [`14-manual-evidence.md`](14-manual-evidence.md).

## Signing

`internal/sign` holds the one implementation: `Encode`, `Sign`, `Verify` and the typed wrappers
`Envelope`/`VerifyEnvelope`/`EncodeEnvelope` and `Manifest`/`VerifyManifest`/`EncodeManifest`.

1. Generate a fresh Ed25519 keypair from the system CSPRNG.
2. Encode the object without its `signature` field (omitted, not null) as canonical JSON. For an
   envelope the signed object is `{format_version, produced_at, records}`
   (`sign.envelopeSigningBytes`).
3. Sign the bytes, store the raw 32-byte public key and the 64-byte signature (base64 in JSON) in
   `signature`.
4. Zero the private key (`ed25519Signer.Sign`).

Canonical JSON: UTF-8, no insignificant whitespace, object keys sorted, RFC 8259 string escaping,
shortest round-trippable numbers, array order kept.

The keypair is per file, never per run. Every envelope gets its own, and the manifest gets
another. The manifest signature covers `file_hashes`, which covers every other file: a
single-level Merkle tree. `result.json` and `summary.json` are unsigned but hashed.

## Verification

The reference verifiers are `sign.VerifyEnvelope` and `sign.VerifyManifest`. `sigcomply report
--view integrity` verifies each run's manifest signature, recomputes its `file_hashes`, and
flags any file in the run folder the manifest does not list (`buildIntegrity` in
`internal/report/report.go`). It reports every failing file, not the first. It does not verify
envelope signatures. The other report views read only `result.json` files the manifest lists. The
Evidence SPA's `/verify` page checks an envelope in the browser.

For one envelope, with no other state:

1. Parse the file and remove `signature`.
2. Canonicalize `{format_version, produced_at, records}`.
3. Base64-decode `public_key` and `value` and call `ed25519.Verify`.

For a run folder:

1. Verify `manifest.json` the same way (signed object = the manifest minus `signature`).
2. Recompute the SHA-256 of every path in `file_hashes` and compare.
3. Optionally verify each envelope's own signature.

For manual evidence, hash the customer's copy of each uploaded file and compare it with
`source_files` in the signed record.

A valid signature proves the file is unchanged since someone signed it with the embedded key. It
does not prove the CLI signed it: the public key travels in the file, so anyone with vault write
access can rewrite a file, re-sign it, and recompute and re-sign the manifest. Tamper resistance
needs write-once storage (S3 Object Lock, GCS Bucket Lock, Azure immutable storage). See
[`SECURITY.md`](../../SECURITY.md) §Threat model for the full list.

## Period state

The CLI keeps no cross-run history. A reader derives the
state of a period on read: list `{framework}/{period_id}/run_*/`, and for each policy take the
result from the latest run (by `completed_at`) that produced one. `sigcomply report --view
latest` does this. Run folders are immutable, so the per-run history of every policy stays
readable; analysing that history over time is out of the CLI's scope
([`06-aggregation.md`](06-aggregation.md)).

## Backends

All access goes through `core.Vault` (`Init`, `PutEnvelope`, `PutJSON`, `PutBinary`,
`GetBinary`, `List`). Shipped backends: `local`, `s3` (on-prem S3-compatible stores via
`endpoint` + `force_path_style`), `gcs`, `azure_blob`. One backend serves the whole vault. The
manual-evidence upload bucket is configured separately under `sources.manual.pdf`. Keys per
backend are owned by [`docs/configuration.md`](../configuration.md).

### Adding a backend

A backend is a factory registered with `vault.RegisterBackend` (in-tree) or `plugin.RegisterVaultBackend`
(project-local). In-tree: [`docs/claude/recipes.md`](../claude/recipes.md). Project-local:
[`07-extensibility.md`](07-extensibility.md) §Custom vault backends. The factory receives the open
`spec.VaultConfig` bag and must resolve its credentials eagerly, so a run that cannot write
evidence fails before it collects.

## Permissions

| Actor | Needs | Why |
|---|---|---|
| CI runner, scheduled role | write and list on the vault prefix, read and write on `state/`; no delete | Writes run folders, reads and advances state shards. Carry-forward stores a pointer to the prior envelope; it does not read the envelope. |
| CI runner, on-push role | write and list on the vault prefix, no write on `state/`; no delete | A `--pr` run (or any run in a PR/MR pipeline) writes its run folder and never advances state. Its role is the one a branch can assume, so denying `state/` keeps a branch from choosing what the next scheduled run carries forward ([09-ci-execution-model.md](09-ci-execution-model.md)). |
| `sigcomply report` | read and list on the vault prefix | Reads run folders. |

Scope the CI role to the vault prefix only, and use the CI provider's OIDC federation instead of
long-lived keys (`sigcomply init-ci` GitHub templates use `aws-actions/configure-aws-credentials`
with `role-to-assume`). Set retention to what your auditor requires as a bucket lifecycle rule.

## Schema versions

| Artifact | Version |
|---|---|
| `manifest.json` | `run.v1` |
| `summary.json` | `summary.v2` |
| envelope | `envelope.v1` |
| record payload | the record's `type` (`directory_user.v2`) |
| `result.json` | none (raw `core.PolicyResult`) |

Rules: adding an optional field keeps the version; renaming, removing or changing the meaning of
a field coins a new version; a reader that meets an unknown version refuses to interpret the file.
