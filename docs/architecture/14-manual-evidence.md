# 14. Manual evidence

What the CLI does with customer-uploaded evidence files, what it deliberately does not do, and why.
This doc owns the manual-evidence contract (Invariant #2 in [`AGENTS.md`](../../AGENTS.md)). Read it
before you touch `internal/sources/manual/`, `internal/evaluator/manual_check.go`,
`internal/vendorfanout/` or a framework's `manualSpecs()`.

Customer-facing usage: [`docs/guides/manual-evidence.md`](../guides/manual-evidence.md). Config keys:
[`docs/reference/sources.md`](../reference/sources.md) §Manual evidence. Period derivation:
[`10-cadence-model.md`](10-cadence-model.md) §Manual evidence periods.

## The flow in one paragraph

A policy with `evidence_mode: manual` names a catalog entry (`core.Policy.CatalogEntry`). The
planner binds it to the `manual.pdf` source on the synthetic `_manual` slot
(`planner.resolveManualBinding`). The `manual.pdf` plugin lists the entry's folder in the
project's one manual-evidence bucket, converts and merges what it finds, runs byte-level checks
and emits one `signed_document` record. The collector signs that record into an envelope like
any other record. The evaluator runs the universal presence check (`evaluateManual`);
`pass_when:` and `rule:` are not used for manual policies.

## Where the files live

One `manual.pdf` source and one bucket per project (a project-level singleton; config validation
in `internal/spec/project_config.go` enforces it). Backends: `local`, `s3`, `gcs`, `azure_blob`,
registered through `manual.RegisterReader`.

The folder for one entry and one period is built by `manual.FolderPrefix`:

```
{prefix}{evidence_catalog_id}/{period_id}/
```

- `{prefix}` is normalized to end in exactly one `/` (`manual`, `manual/` and `manual//` are the
  same folder); an empty prefix stays empty. The default is `manual/`.
- `{period_id}` is the entry's own cadence window from `planner.CadencePeriod` (annual `2026`,
  quarterly `2026-Q1`, monthly `2026-01`, weekly `2026-W03`, daily `2026-01-15`), not the run's
  period. The planner uses the declared cadence of the manual policy that owns the entry
  (`planner.manualCatalogCadences`, the same cadence the framework's manual catalog carries), so
  a `policies.<id>.cadence` override never moves the folder, and a policy switched to manual
  with `catalog_entry` reads the entry's folder, not one keyed on its own cadence. The mapping per calendar type is in `10-cadence-model.md`.
- The bucket is not part of the key. `manual.FolderURI` adds it only for display
  (`s3://`, `gs://`, `azure://`, `file://`).

`FolderPrefix` is the single source of truth. `sigcomply evidence due` (`internal/manualdue`)
calls it, so the folder it reports empty is the folder `check` reads. The Evidence SPA mirrors it
in `src/lib/storage-path.ts`; change both together.

## What the plugin checks

`Plugin.scanFolder` in `internal/sources/manual/manual.go`, in order:

1. List the folder. No files: `file_present=false`. The evaluator fails the policy with
   "manual evidence not found; expected files in: <folder URI>".
2. Classify each file by extension (`fileconv.SupportedExt`: PDF, JPEG, PNG, GIF, TIFF, WebP,
   BMP). An unsupported file adds `unsupported_file_type` to `validation_failures` and is skipped.
3. Fetch each supported file, SHA-256 its original bytes, and convert images to PDF
   (`fileconv.ToPDF`, pure Go). Each file gets a `source_files[]` entry: filename, type,
   `sha256`, upload time, `converted`. A conversion error adds `conversion_failed`.
4. Merge all PDF parts (`pdfmerge.Merge`, pdfcpu). A merge error adds `merge_failed`.
5. Run `validatePDF` on the merged bytes: at least 100 bytes, a `%PDF-` prefix, at least one
   `/Page` marker. Stdlib byte checks only, no PDF parser.
6. Temporal window: the latest upload time must lie in
   `[period_start, period_end + grace]` (`isInTemporalWindow`). Grace comes from the catalog
   entry (`manualcatalog.GraceForCadence`: 15 days for quarterly, 30 days otherwise).
7. Prior-period copy check, only when no failure so far and the planner supplied
   `prior_period_id` (the previous cadence window, so last year for an annual entry). The plugin
   compares `sourceFingerprint` (SHA-256 over the sorted `filename:sha256` list) of this folder
   and the prior folder. Identical sets add `copy_paste_of_prior_period`. A missing or empty
   prior folder is not a failure.

The record's `file_hash` and `file_size` describe the merged PDF. `file_valid` is true only when
files are present and `validation_failures` is empty.

The evaluator (`evaluateManual`) then decides, in this order: no record is `error`;
`file_present=false` is `fail`; `in_temporal_window=false` with a merged PDF (`file_hash` set) is
`fail`; `file_valid=false` is `fail` with the failures listed; otherwise `pass`. With no merged
PDF (every file unsupported or unconvertible, or the merge failed) the window was never judged,
so the failure names the `validation_failures`, such as `unsupported_file_type`.

## What is signed and stored

- The collector signs the `signed_document` record into a per-file envelope (Invariant #3). The
  record carries `source_files[].sha256` for every original file and the merged PDF's hash.
- The merged PDF is written to the run folder at
  `policies/{policy_id}/attachments/{evidence_catalog_id}.pdf`. The plugin hands the bytes to the
  collector as a `core.Attachment` on the record (never serialized, so the envelope does not grow);
  the collector writes it with `PutBinary`, so it is in the manifest's `file_hashes`. Its SHA-256
  equals the record's `file_hash` and its size `file_size`. No PDF is written when nothing was
  merged (empty folder, only unsupported files, or `merge_failed`). A failed write errors the
  policy, like a failed envelope write.
- The original uploads are not copied. An auditor checks them in the manual-evidence bucket
  against `source_files[].sha256`. No SigComply command re-reads the bucket to compare.
- Nothing about the files crosses the aggregation boundary. The cloud payload gets the policy's
  status and counts only (Invariant #1).

## Fan-out entries

A catalog entry may declare `fanOut` (`manual.FanOutVendors` or `manual.FanOutSubserviceVendors`).
The members come from project config (`experimental.vendors`), resolved onto the runtime catalog
by `internal/vendorfanout`. The plugin then scans one folder per member:

```
{prefix}{evidence_catalog_id}.{member_id}/{period_id}/
```

`Plugin.collectInstances` runs the same `scanFolder` for each required member and emits one record
with a per-member verdict plus `instances_total` and `instances_satisfied`. A non-required member
is an approved exemption: no folder is listed, it counts as satisfied, and its
`exemption_reason` and `approved_by` stay in the signed record. A member may declare
`assurance_period_end`; if it ends more than 15 months (`manual.AssuranceMaxAge`) before the
period start, the member gets `assurance_out_of_date`. The date is declared in config, never read
from the PDF.

Each member with a merged PDF gets its own attachment,
`policies/{policy_id}/attachments/{evidence_catalog_id}.{member_id}.pdf`, whose SHA-256 is that
member's `instances[].file_hash`. The record has no top-level `file_hash` for a fan-out entry.

The evaluator (`evaluateManualInstances`) fails the policy if any required member is unsatisfied
and sets `resources_evaluated` / `resources_failed` from the member counts.

Rules:

- Fan-out multiplies folders, not policies. One policy ID, one binding, one envelope, one state
  shard. A policy per member would make the member slug an identity that state shards,
  `policies.<id>` overrides, `evidence due` and the `report --view coverage|soa` join key on, and
  it would put the vendor list on the wire through `policy_id`.
- Fan-out is not a third evidence flow. Only `automated` and `manual` exist.
- Resolve members in `internal/vendorfanout`, never in a framework. The exported catalog
  (`manualcatalog.Entry`, consumed by the SPA) must stay config-independent; its field count is
  pinned by `internal/manualcatalog/catalog_test.go`.
- An entry with no members behaves exactly like a single-folder entry.

## What the CLI does not do

- Read, extract or judge document contents: no text extraction, no signature or expiry parsing,
  no check that the document covers the control. A wrong but well-formed PDF passes.
- Detect fabrication. The CLI signs what it reads.
- Branch on catalog presentation fields. Catalog `type` (`declaration`, `checklist`,
  `document_upload`), `items` and `declaration_text` are hints for the Evidence SPA form helper;
  the evaluator ignores them.

Estate-level completeness ("was every declared source reached?") is a separate opt-in run-level
check (`internal/scope`, `experimental.scope`). It never inspects a document.

## Why it stops here

The product is custody of evidence, not a content validator. Reading document contents would make
the CLI judge what an auditor judges, and a parser that pulls in network-aware dependencies breaks
"evidence without access". Richer inspection, if it is ever built, goes in a separate opt-in path
or a new evidence type (for example `manual.pdf.v2`), never inside `validatePDF`.

The prior-period check fires for every manual entry. Evidence that is legitimately unchanged
between periods gets an exception under `policies.<id>.exceptions`; there is no per-entry
"may repeat" flag in the catalog. Add one only when a real entry needs it.

## Change checklist

- Folder scheme: `manual.FolderPrefix`, `internal/manualdue`, the SPA's `storage-path.ts`, and
  [`docs/guides/manual-evidence.md`](../guides/manual-evidence.md) change together.
- Catalog export shape: `internal/manualcatalog` and the SPA's `src/types/catalog.ts` change
  together; run `sigcomply evidence catalog -o json` to check.
- Catalog entry count: `TestDocFiguresMatchCode` names every doc that quotes it.
- Tests: `internal/sources/manual/manual_test.go`, `instances_test.go`,
  `internal/evaluator/manual_instances_test.go`.
