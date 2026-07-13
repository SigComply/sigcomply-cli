# Manual evidence (SOC 2)

How to satisfy the SOC 2 evidence that no API can collect — policies, HR
exports, signed acknowledgments, penetration-test reports — by uploading
files to your evidence bucket.

Back to the [docs hub](../README.md).

## Two evidence flows, in one sentence each

SigComply has exactly two evidence flows, and every policy declares which
one it uses via `evidence_mode`:

- **Automated** (`evidence_mode: automated`) — a source plugin (AWS, GitHub,
  GCP, Okta, …) calls a read-only API, the result is validated against an
  evidence-type schema, and the policy's `pass_when` rule evaluates it.
- **Manual** (`evidence_mode: manual`) — you upload one or more files to a
  known folder in your own storage; the CLI checks that supported files are
  **present**, **valid**, and **within the temporal window**.

This page is about the manual flow. For the automated flow see
[configure-sources.md](configure-sources.md).

## What the CLI actually checks (and what it does not)

For a manual policy the CLI scans the catalog-resolved folder and, if
supported files are there, it:

1. Accepts these file types: **PDF, JPEG, PNG, GIF, TIFF, WebP, BMP**.
2. Converts every image to PDF and **merges everything into one PDF**.
3. Runs a lightweight validity check (PDF magic bytes, minimum size, at
   least one page).
4. Checks the latest upload timestamp falls inside the temporal window
   (period + grace period).

That is the whole check. The CLI **does not read the contents of your
PDF** — no text extraction, no signature parsing, no completeness or
correctness check. Reviewing what the document actually says is the
auditor's job. The presence, format, and freshness check is what
SigComply automates.

> **The catalog `type` field is a hint, not a behavior.** Entries carry a
> `type` of `document_upload`, `declaration`, or `checklist`. These values
> exist only so the optional [Evidence SPA](#producing-the-pdf) can render
> the right form. **The CLI evaluator does not branch on `type`** — for
> every manual entry the only question is "are supported files present in
> the folder within the temporal window?"

## Manual evidence is a project-level singleton

One repo = one framework = one evidence vault, and likewise **one manual
evidence bucket per project**, configured once under `sources.manual.pdf`.
There is no per-framework or per-entry bucket. Every manual entry lives in
its own subfolder of that one bucket.

## Step 1 — Discover the required entries

List the framework's manual-evidence catalog. This works without any
project config:

```bash
sigcomply evidence catalog -f soc2 -o text
```

The SOC 2 catalog has **40 entries**. Abbreviated output:

```
Manual Evidence Catalog: soc2 (v1.0) — 40 entries

ID                               CONTROL  TYPE             FREQUENCY  NAME
access_review_quarterly          CC6.3    document_upload  quarterly  Access Review Quarterly
code_of_conduct_acknowledgment   CC1.1    declaration      yearly     Code Of Conduct Acknowledgment
incident_response_tested         CC7.3    checklist        yearly     Incident Response Tested
penetration_test_annual          CC8.1    document_upload  yearly     Penetration Test Annual
security_awareness_training      CC1.1    document_upload  yearly     Security Awareness Training
...
```

For the machine-readable form (the same contract the Evidence SPA
consumes):

```bash
sigcomply evidence catalog -f soc2 -o json
```

Each entry looks like:

```json
{
  "id": "security_awareness_training",
  "control": "CC1.1",
  "type": "document_upload",
  "frequency": "yearly",
  "temporal_rule": "retrospective",
  "grace_period": "30d",
  "name": "Security Awareness Training",
  "description": "Employees complete security awareness training.",
  "severity": "medium",
  "tsc": "security"
}
```

The `id` is what you reference from a policy (Step 3). `frequency`,
`temporal_rule`, and `grace_period` define the temporal window the upload
must fall in.

## Step 2 — Configure the manual evidence source

Add a single `manual.pdf` source to `.sigcomply.yaml`. The backend can be
`local`, `s3`, `gcs`, or `azure_blob` (default `local`).

```yaml
schema_version: project.v1
framework: soc2
sources:
  manual.pdf:
    backend: s3                 # local | s3 | gcs | azure_blob
    bucket: my-evidence-bucket
    region: us-east-1
    prefix: manual/
vault:
  backend: local
  path: ./.sigcomply/vault
```

The CLI scans this folder for each manual entry:

```
{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/
```

So for the entry `security_awareness_training` in period `2026-Q1`, with
the config above, you upload files to:

```
s3://my-evidence-bucket/manual/security_awareness_training/2026-Q1/
```

Put any number of supported files in that folder — they are all merged
into one PDF before evaluation.

## Step 3 — Wire a policy to a manual entry

A policy consumes manual evidence when you set `evidence_mode: manual` and
name the `catalog_entry`:

```yaml
policies:
  soc2-cc1.1-security-awareness:
    evidence_mode: manual
    catalog_entry: security_awareness_training
```

`catalog_entry` is required whenever `evidence_mode: manual`. The policy's
`pass_when`/`rule` (if any) is ignored — manual policies only run the
presence + temporal-window + validity check described above.

## Producing the PDF

There are two ways to get a file into the folder, depending on the entry:

- **(a) Use the optional Evidence SPA** for `declaration` and `checklist`
  entries. Fill in a form in the browser, click through the items, and
  download `evidence.pdf` — then upload it to the entry's folder. The SPA
  is static, has no backend, and uploads nothing to a server. See
  [verify-evidence.md](verify-evidence.md#the-evidence-spa) and the SPA
  repo: <https://github.com/SigComply/sigcomply-evidence-spa>.
- **(b) Produce your own PDF** for everything else — HR exports, training
  certificates, penetration-test reports, scanned signed documents. The
  SPA hides these entry types because you generate the artifact yourself
  outside the tool. Any supported file type works; images are converted to
  PDF automatically.

Either way the CLI treats the result identically: files in the folder,
merged, checked for presence and freshness.

## Verifying a manual upload was accepted

After a run, inspect the vault:

```bash
sigcomply report --period 2026-Q1 --view latest
```

If the folder was empty or held no supported files, the manual policy
fails with a structured message pointing at the expected folder (see
[troubleshooting.md](troubleshooting.md#manual-evidence-expected-files)).

## Next steps

- [verify-evidence.md](verify-evidence.md) — verify signed evidence and use
  the Evidence SPA `/verify` page.
- [configure-sources.md](configure-sources.md) — the automated evidence flow.
- [cloud-dashboard.md](cloud-dashboard.md) — submit aggregated results to the
  optional dashboard.
- [../configuration.md](../configuration.md) — full `.sigcomply.yaml`
  reference.
- Back to the [docs hub](../README.md).
