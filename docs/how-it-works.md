# How SigComply works

SigComply is a CLI, `sigcomply`, that runs as a step in your CI pipeline. It reads configuration
from your cloud and SaaS accounts with the credentials the pipeline already has, checks that the
documents your auditor expects are in a folder you own, and evaluates SOC 2 or ISO 27001 policies
against both. It signs every piece of evidence and writes it, with the results, to a bucket you
own: the vault. Nothing leaves your pipeline unless you turn on SigComply Cloud, and then only
pass/fail counts per policy and details of the run, such as the repository and commit.

```
  Your CI pipeline (GitHub Actions or GitLab CI)
  +---------------------------------------------------------------+
  |  sigcomply check                                              |
  |                                                               |
  |   1. read cloud and SaaS APIs  <--  pipeline credentials      |
  |      (AWS, GCP, Azure, GitHub,      (OIDC role or CI secret)  |
  |       GitLab, Okta, AD)                                       |
  |   2. check the manual-evidence folder for this period         |
  |   3. evaluate policies                                        |
  |   4. sign the evidence and a manifest hashing every file      |
  +-----------------------------|---------------------------------+
                                |                 :
                                v                 : counts only, optional
              Your bucket (the vault)             v
              signed evidence, results,      SigComply Cloud
              merged PDFs, manifest.json     (dashboard, reports)
```

You can try all of this on your laptop with no cloud account: see the [Quickstart](quickstart.md).

## What happens in one run

`sigcomply check` runs these stages in order.

1. Plan. The CLI reads `.sigcomply.yaml`, works out the audit period from the current UTC time,
   picks the policies to evaluate (all of them, or with `--scheduled` the ones that are due),
   and binds each policy to the configured sources that can feed it.
2. Collect. Each source reads its provider's API and returns evidence records. The CLI checks
   every record against the JSON Schema of its evidence type, then signs the records and writes
   them to the vault. If a source fails or returns a record that doesn't match its schema, the
   policy that needed it gets the status `error`.
3. Evaluate. Each policy runs against the records it was bound to and gets a status: pass,
   fail, skip, error, not applicable, waived, or carried forward from an earlier run.
4. Write results. The CLI writes each policy's `result.json`, a `summary.json`, and a signed
   `manifest.json` that lists the SHA-256 hash of every file in the run.
5. Submit (optional). If cloud submission is on, the CLI sends counts to SigComply Cloud.
6. Exit. The exit code tells CI what happened.

| `check` exit code | Meaning |
|---|---|
| `0` | No policy failed |
| `1` | A policy failed (a violation) |
| `2` | Execution error, for example a policy with status `error` or a failed vault write |
| `3` | Configuration error, for example an invalid `.sigcomply.yaml` |

When a run has both an error and a failed policy, it exits `2`. A violation fails the build by
default. To keep the build green while policies fail, set `ci.fail_on_violation: false`; it
doesn't change exit `2` or `3`. [Commands](reference/commands.md#exit-codes) has the full rules.

## Automated evidence

Credentials stay in your pipeline: an AWS role the job assumes through OIDC, or secrets stored
in your CI. SigComply never receives them. You list the sources to read under `sources:` in
`.sigcomply.yaml`; having a credential is not enough for the CLI to use it.

Sources make read calls only. One exception: `aws.iam` calls `iam:GenerateCredentialReport`,
which asks AWS to build the account's credential report before the CLI reads it. Every API
action each source calls is in [Sources](reference/sources.md).

Each source turns the provider's responses into normalized evidence records of a named type,
such as `directory_user` for a user account in AWS IAM, Okta or Google Workspace. The vault
stores those records, not the provider's responses as returned. This is what lets one policy,
"MFA enforced for all users", work with any identity provider.

The shipped policies are declarative definitions written in Go, so you can read exactly what
each one checks in the source code. Rego (the Open Policy Agent language) is only for
policies you add to your own project.

A policy that no configured source can feed is skipped. A skipped policy is left out of the
compliance score, so a missing source raises the score instead of lowering it. `check` lists every skipped
policy and the evidence type it needs. [Concepts](concepts.md#what-the-score-does-not-tell-you)
explains this in detail.

## Manual evidence

Some controls have no API to ask: a signed NDA policy, a business continuity plan, a training
record. The framework's catalog lists one entry per document the auditor expects. Each entry
has a type: `document_upload` (a file you produce elsewhere), `declaration` or `checklist`.

You put the files for an entry in a folder named after the entry and its period:

```
<prefix><catalog_id>/<period>/
manual/business_continuity_plan/2026/       # annual entry
manual/access_review_quarterly/2026-Q4/     # quarterly entry
```

The default prefix is `manual/`, in the storage configured for the `manual.pdf` source. Each
entry has its own period: a calendar year for annual entries, a quarter for quarterly ones,
with a grace period after it ends for late uploads (15 days for quarterly entries, 30 days
for the others). Supported file types are PDF, JPEG
(`.jpg`, `.jpeg`), PNG, GIF, TIFF (`.tif`, `.tiff`), WebP and BMP.

For each entry, the CLI checks that:

- a supported file is in the folder,
- the latest file was uploaded within the period plus its grace period,
- the files are not byte-identical to the previous period's.

The CLI converts images to PDF and merges every file into one PDF, then runs basic checks that
the result is a valid PDF. It records the SHA-256 hash of each original file and of the merged
PDF in a signed evidence record, and stores the merged PDF in the vault next to it.

The CLI never reads or judges what a document says. A policy passes when the right files are in
the right folder at the right time. Whether the content meets the control is your auditor's
decision.

To see which folders are still empty, run `sigcomply evidence due`. For `declaration` and
`checklist` entries, the [Evidence SPA](https://sigcomply.github.io/sigcomply-evidence-spa/)
renders a form and turns your answers into a PDF in your browser. It uploads nothing; you put the
PDF in the folder yourself. [Manual evidence](guides/manual-evidence.md) has the details.

## Signing and verification

The CLI signs each evidence file with Ed25519, using a new key pair for every signature. It
stores the public key and the signature inside the file and discards the private key. Each run
also writes `manifest.json` with the SHA-256 hash of every file in the run, signed the same way.

You can verify evidence two ways:

- `sigcomply report --period <id> --view integrity`, where `<id>` is the run period such as
  `2026-Q4`, re-hashes every file in the period's runs,
  checks each manifest signature, and flags files that are missing or that the manifest does not
  list.
- The [`/verify` page](https://sigcomply.github.io/sigcomply-evidence-spa/verify) checks one
  envelope, and its merged PDF for a manual policy, in your browser. Nothing is uploaded.

What this proves: a file changed or removed after the run fails verification.

What it does not prove: who signed the file. The public key travels in the file, so anyone with
write access to your bucket can replace a file and sign it again with a new key, and the result
looks like an original. Runs are not chained to each other either. To protect evidence against
deliberate changes, make the bucket write-once: S3 Object Lock, GCS Bucket Lock, or Azure
immutable blob storage. The CLI doesn't configure that for you. [SECURITY.md](../SECURITY.md)
has the threat model.

## What leaves your pipeline

Nothing, unless all of these hold:

- `cloud.base_url` is set in `.sigcomply.yaml` (or `--cloud-url` is passed),
- `cloud.project_id` is set,
- the run can get an OIDC token: it runs in GitHub Actions or GitLab CI, or you pass `--cloud`,
- the run covers every policy: `sigcomply check` with no filter, or `--scheduled`,
- you didn't pass `--no-cloud`.

[Commands](reference/commands.md#sigcomply-check) has the full rule.

| Sent to SigComply Cloud | Stays in your pipeline and bucket |
|---|---|
| Each policy's ID, controls, status and counts (resources evaluated, resources failed) | Evidence records and envelopes |
| Run summary counts and compliance score | Uploaded documents and merged PDFs |
| Framework and period | File hashes and signatures |
| Repository, branch, commit and commit time | Names, emails, usernames, ARNs and account IDs |
| CLI version and a link to the CI run | Each run's `manifest.json` and `result.json` |
| | Your credentials |

The exact field list is the `SubmissionPayload` type in
[`internal/core/cloud.go`](../internal/core/cloud.go); it has no free-form fields and no list of
failing resources, and a test fails the build if one is added. To see what a run would send without sending it, run
`sigcomply check --capture-cloud-payload payload.json`. [Cloud dashboard](guides/cloud-dashboard.md)
covers setup.

## SigComply Cloud

SigComply Cloud is the paid dashboard, with a free trial. It works only from the counts above.

- It keeps every submitted run for each project.
- It builds reports (Compliance Summary, Drift Analysis, Control Matrix) as PDF, CSV or JSON
  over a date range you choose, for example your audit window.
- It has an auditor portal: you grant an auditor read-only access to one project, optionally
  with an expiry date.
- It emails your organization's owner when a project's scheduled checks stop arriving.

The ISO 27001 Statement of Applicability doesn't need SigComply Cloud: the CLI produces it for
free with `sigcomply report --view soa`.

## What SigComply doesn't do

- Vendor security reviews, security awareness training, device monitoring or background checks.
  It checks that the documents these produce are on file.
- A public trust center.
- The audit. An auditor decides whether you are compliant; SigComply collects evidence and
  evaluates policies.

## Implementation details

- [Concepts](concepts.md): evidence flows, how policies bind to sources, the limits of the score.
- [Commands](reference/commands.md) and [Configuration](configuration.md): every command, flag
  and config key.
- [SECURITY.md](../SECURITY.md): threat model and how to report a vulnerability.
- [Frameworks](reference/frameworks.md): what each framework covers.

The architecture docs are written for contributors:

- [03-policy-spec.md](architecture/03-policy-spec.md): how a policy is defined.
- [05-vault-layout.md](architecture/05-vault-layout.md): the vault layout and signing.
- [06-aggregation.md](architecture/06-aggregation.md): how results become counts, and the
  privacy boundary.
- [10-cadence-model.md](architecture/10-cadence-model.md): cadences and periods.
- [14-manual-evidence.md](architecture/14-manual-evidence.md): manual evidence end to end.
