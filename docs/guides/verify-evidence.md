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

   `fail` names the first file whose hash no longer matches the manifest. The command exits `0`
   whether runs pass or fail, so read the output rather than the exit code.

3. For a file you can keep, write JSON or CSV with `--out`:

   ```bash
   sigcomply report --period 2026-Q4 --view integrity --format json --out integrity.json
   ```

Other views of the same vault (`latest`, `exceptions`, `scope`, `coverage`, `soa`) and every
flag: [commands reference](../reference/commands.md#sigcomply-report). The `coverage` view
separates controls checked against infrastructure from controls backed only by a document on
file. For SOC 2, 27 of 43 criteria are backed only by documents.

## Verify one file in the browser

The Evidence SPA `/verify` page checks one envelope's signature in your browser. Nothing is
uploaded.

1. Copy an envelope file from the vault, for example
   `policies/soc2.cc1.1.security_awareness_training/envelopes/signed_document__manual.pdf_security_awareness_training.json`.
2. Open <https://sigcomply.github.io/sigcomply-evidence-spa/verify>.
3. Drop the envelope file on the page, choose it, or paste its JSON.
4. Read the verdict. A valid signature means the envelope is unchanged since the CLI signed it.
5. Optional, for a manual evidence envelope: drop the original document on the PDF check. The
   page hashes it and compares the hash with the envelope's `file_hash`.

Limits of the PDF check:

- The vault does not store the uploaded documents or the merged PDF. Take the file from the
  manual evidence folder (`{prefix}{entry ID}/{period}/`).
- The hash matches only when that folder held exactly one PDF. For several files, or images, the
  envelope's hash is of the merged PDF, which is not stored anywhere. The envelope still lists
  each source file's name and SHA-256 under `source_files`; compare those with `shasum -a 256`.
- A fan-out envelope (one folder per vendor) has no top-level `file_hash`, so the page checks
  only its signature.

## Next steps

- [Concepts](../concepts.md): what the signatures and counts do and don't prove.
- [Upload manual evidence](manual-evidence.md).
