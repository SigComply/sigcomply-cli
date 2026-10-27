# Verify evidence

Check that the signed evidence in a SigComply vault has not changed since the CLI wrote it:
the whole vault with `sigcomply report`, or one file in the browser. Both run offline, with no
login and no SigComply Cloud.

Each run folder in the vault (for example `soc2/2026-Q4/run_20261026T201233Z_31e1022c/`) holds:

- one signed envelope per evidence file, under `policies/<policy ID>/envelopes/`. Each envelope
  is JSON with `format_version`, `produced_at`, `records` and a `signature` (`algorithm`,
  `public_key`, `value`). The CLI signs each envelope with a fresh Ed25519 key and discards the
  private key.
- `manifest.json`, which lists the SHA-256 hash of every file in the run (`file_hashes`) and is
  signed the same way.

A passing check shows a file is unchanged since it was signed. It does not stop someone with
write access to the vault from replacing a file and signing it again with a new key. For that,
make the vault storage write-once or versioned (S3 Object Lock, GCS Bucket Lock, Azure immutable
storage). Threat model: [`SECURITY.md`](../../SECURITY.md).

## Prerequisites

- Read access to the vault, and the CLI installed ([install guide](install.md)) for the first
  task.
- The period to check, for example `2026-Q4`. Run folders are grouped by period in the vault.

## Verify a whole period with the CLI

1. From the repository root, run the integrity view:

   ```bash
   sigcomply report --period 2026-Q4 --view integrity
   ```

   To check a vault in a bucket, or without the project config, pass the vault and framework:

   ```bash
   sigcomply report --period 2026-Q4 --view integrity --vault s3://my-vault-bucket -f soc2
   ```

2. Read the `STATUS` column. Each run in the period is one row:

   ```text
   RUN_PATH                                    STATUS  FILES_OK  DETAIL
   soc2/2026-Q4/run_20261026T201228Z_2771326f  pass    95/95     -
   soc2/2026-Q4/run_20261026T201228Z_30e5ba7f  fail    57/95     mismatch: policies/soc2.cc7.3.incident_response_plan/result.json
   ```

   `fail` names the first file whose hash no longer matches the manifest. The command exits `1`
   when any run fails and `0` when every run passes, so a script can rely on the exit code.

3. For a file you can keep, write JSON or CSV with `--out`:

   ```bash
   sigcomply report --period 2026-Q4 --view integrity --format json --out integrity.json
   ```

Other views of the same vault (`latest`, `exceptions`, `scope`, `coverage`, `soa`) and every
flag: [commands reference](../reference/commands.md#sigcomply-report). The `coverage` view
separates controls with an automated check mapped from controls backed only by a document on
file. For SOC 2, 27 of 43 criteria are backed only by documents. It classifies each control by
the policies mapped to it (automated or document), not by which policies ran, so a control whose
automated policy was skipped still counts as automated. Its `This period` section then says how
many automated controls were inspected and how many only skipped. To see each policy's result,
use `sigcomply report --period 2026-Q4 --view latest`.

## Verify one file in the browser

The Evidence SPA `/verify` page checks one envelope's signature in your browser. Nothing is
uploaded.

1. Copy an envelope file from the vault, for example
   `policies/soc2.cc1.1.security_awareness_training/envelopes/signed_document__manual.pdf_security_awareness_training.json`.
2. Open <https://sigcomply.github.io/sigcomply-evidence-spa/verify>.
3. Drop the envelope file on the page, choose it, or paste its JSON.
4. Read the verdict. A valid signature means the envelope is unchanged since the CLI signed it.
5. Optional, for a manual evidence envelope: drop the merged PDF on the PDF check. The page
   hashes it and compares the hash with the envelope's `file_hash`, or, for a fan-out envelope,
   with each vendor's `instances[].file_hash`.

The merged PDF is in the same run folder as the envelope:

```
policies/{policy_id}/attachments/{entry ID}.pdf
```

for example
`policies/soc2.cc1.1.security_awareness_training/attachments/security_awareness_training.pdf`.
It is listed in the run's `manifest.json`, so `sigcomply report --view integrity` checks it too.

Limits of the PDF check:

- The vault stores the merged PDF, not the original uploads. To check an original, take it from
  the manual evidence folder (`{prefix}{entry ID}/{period}/`) and compare its `shasum -a 256` with
  the matching `source_files` entry in the envelope.
- No PDF is stored when nothing could be merged: an empty folder, only unsupported files, or a
  failed merge. The envelope then has no `file_hash`.
- A fan-out envelope (one folder per vendor) stores one merged PDF per vendor that uploaded
  files, at `attachments/{entry ID}.{vendor ID}.pdf`. The page shows each vendor's verdict and
  matches a dropped PDF against that vendor's `instances[].file_hash`.

## Next steps

- [Concepts](../concepts.md): what the signatures and counts do and don't prove.
- [Upload manual evidence](manual-evidence.md).
