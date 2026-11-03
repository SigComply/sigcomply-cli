# Upload manual evidence

Supply the documents that no API can produce (policies, training records, access reviews, signed
declarations) so the CLI can collect them for SOC 2 or ISO 27001. The examples use SOC 2; ISO
27001 works the same way.

For each entry, the CLI checks that the folder holds supported files for the entry's period,
merges them into one PDF and signs a record of their hashes. It never reads what a document says;
your auditor does. Background: [Concepts](../concepts.md).

## Prerequisites

- The CLI installed ([install guide](install.md)), to list entries and check your uploads.
- A `.sigcomply.yaml` with `framework:` set. `sigcomply init` writes one with a local manual
  evidence source.
- Write access to the storage that holds the documents: a local folder, or an S3, GCS or
  Azure Blob bucket.

## 1. Configure the manual evidence source

Each project has one manual evidence source, `manual.pdf`. `sigcomply init` writes a local one:

```yaml
sources:
  manual.pdf:
    backend: local
    path: ./evidence
```

Use a bucket when the CLI runs in CI. A local path in CI is the repository checkout, where every
file's modification time is the checkout time, not the time you added it. For a bucket, use
`s3`, `gcs` or `azure_blob`:

```yaml
sources:
  manual.pdf:
    backend: s3
    bucket: my-evidence-bucket
    region: us-east-1
    prefix: manual/
```

`prefix` defaults to `manual/`. The keys for each backend are in the
[sources reference](../reference/sources.md#manual-evidence). The CLI reads a bucket with the
cloud credentials of the environment it runs in, so `evidence due` and `check` need read access
to the bucket.

You don't need a `policies:` block. Every built-in manual policy reads its own catalog entry.

## 2. Find what to upload

List the manual entries for your framework:

```bash
sigcomply evidence catalog -f soc2 -o text
```

The SOC 2 catalog has **52 entries**:

```text
Manual Evidence Catalog: soc2 (v1.0) — 52 entries

ID                                CONTROL  TYPE             FREQUENCY  NAME
access_review_quarterly           CC6.3    document_upload  quarterly  Quarterly Access Review
accountability_for_controls       CC1.5    declaration      yearly     Accountability for Controls
background_check_policy           CC1.4    document_upload  yearly     Background Check Policy
...
```

`-o json` adds each entry's description, time rule (`temporal_rule`) and grace period
(`grace_period`).

To list the folders that are still empty, with the exact upload path for each:

```bash
sigcomply evidence due --all
```

```text
manual evidence: 52 of 52 entries have an empty folder (run period 2026-Q4)
  ENTRY                             CADENCE    PERIOD   DUE IN  UPLOAD TO
  access_review_quarterly           quarterly  2026-Q4  66d     file://./evidence/manual/access_review_quarterly/2026-Q4/
  accountability_for_controls       annual     2026     66d     file://./evidence/manual/accountability_for_controls/2026/
```

Without `--all`, `evidence due` lists only the folders whose period ends within 30 days
(`--within-days` changes that).

### Make a declaration or checklist PDF in the Evidence SPA

For entries of type `declaration` or `checklist`, you can produce the PDF in the browser with the
[Evidence SPA](https://sigcomply.github.io/sigcomply-evidence-spa/). It runs entirely in your
browser and sends nothing to a server. Entries of type `document_upload` (exports, certificates,
reports) don't appear there; produce those files yourself.

1. Open <https://sigcomply.github.io/sigcomply-evidence-spa/> and pick your framework.
2. Open the entry you need.
3. Check the period, accept the declaration or confirm each checklist step, and enter who
   completed it.
4. Select **Download evidence.pdf**.
5. Upload the file as in step 3. The SPA shows the path for the default `manual/` prefix and
   calendar periods. If your project sets another prefix or a fiscal or custom calendar, use the
   path from `sigcomply evidence due --all` instead.

## 3. Upload the files

Put the files in the entry's folder:

```text
{bucket or path}/{prefix}{entry ID}/{period}/
```

`{period}` is the entry's own cadence window, not the period of the run:

| Entry frequency | Folder | Example |
|---|---|---|
| daily | `YYYY-MM-DD` | `2026-01-15` |
| weekly | ISO week | `2026-W03` |
| monthly | `YYYY-MM` | `2026-01` |
| quarterly | `YYYY-Qn` | `2026-Q1` |
| yearly (`annual` in `evidence due`) | `YYYY` | `2026` |

So an annual document goes in once a year: `manual/security_awareness_training/2026/` covers
every run in 2026. If your project sets a fiscal or custom calendar, the folder names differ;
take the path from `sigcomply evidence due --all`.

### When to upload

Upload during the period the document covers.

- The upload time is the object's last-modified time (for a local folder, the file's
  modification time). Uploading a file again resets it.
- A file uploaded before the period starts fails as outside the window, so you can't stage next
  year's evidence early.
- Once a period ends, runs read the next period's folder, so a file added to the old folder later
  is never checked. The entry's grace period after the end only absorbs clock differences.
- Period boundaries are in UTC. A file uploaded at 21:00 on 31 March in New York (UTC-4) is
  01:00 on 1 April UTC, so it falls in the second quarter, not the first.

### File rules

- Supported formats: PDF, JPEG, PNG, GIF, TIFF, WebP and BMP. The CLI converts images to PDF and
  merges all files in the folder into one PDF. Any other file in the folder fails the policy
  with `unsupported_file_type`.
- Size limits: each file at most 100 MB (`file_too_large`), and each image at most 50 megapixels
  (`conversion_failed`). Split a larger file, or downscale the image or save it as a PDF.
- The CLI ignores hidden files (such as `.DS_Store`), `Thumbs.db`, `desktop.ini`, the empty
  object a bucket console's "Create folder" makes, and anything in a subfolder. Put the files
  directly in the period folder. In a local folder, symbolic links are ignored too; copy the file
  in instead.
- A PDF that opens without a password is accepted, even if it restricts printing or editing.
- Don't copy last period's file unchanged. If every file in the folder is byte-identical to the
  previous period's, the policy fails with `copy_paste_of_prior_period`.

## 4. Run the check

```bash
sigcomply check
```

## Verify

A policy whose folder holds a valid file in its window passes:

```text
  [pass] soc2.cc1.1.security_awareness_training — CC1.1
```

One with no file fails and names the folder it read:

```text
  [fail] soc2.a1.2.business_continuity_plan — A1.2
      ↳ manual evidence not found; expected files in: file://./evidence/manual/business_continuity_plan/2026/
```

`sigcomply report --period 2026-Q4 --view latest` shows the same results from the vault.

## Optional: run an automated policy from a document

When an API can't answer a policy for your estate, you can supply a document for it instead. Set
the policy's evidence mode and name a catalog entry:

```yaml
policies:
  soc2.cc8.1.approval_precedes_merge:
    evidence_mode: manual
    catalog_entry: code_review_policy
```

The policy then checks the entry's folder and ignores its automated rule. The folder follows the
entry's cadence, not the policy's: with the annual `code_review_policy` entry, this daily policy
reads `code_review_policy/2026/`, the same folder as that entry's own policy.

`sigcomply report --view coverage` marks the control as `(overridden)`, so your auditor can see
the change.

## Next steps

- [Declare a vendor register](vendor-risk.md) to collect evidence per vendor.
- [Collect the ISO 27001 clause documents](isms-clauses.md).
- [Verify evidence](verify-evidence.md).
