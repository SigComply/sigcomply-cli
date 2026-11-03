# How SigComply works

SigComply is a CLI, `sigcomply`, that runs as a step in your CI pipeline. It reads configuration
from your cloud and SaaS accounts with the credentials the pipeline already has, checks that the
documents your auditor expects are in a folder you own, and evaluates SOC 2 or ISO 27001 policies
against both. It signs every piece of evidence and writes it, with the results, to a bucket you
own: the vault. With the dashboard turned on, only counts and run details leave
([details](#what-leaves-your-pipeline)).

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
              signed evidence, results,      SigComply dashboard
              merged PDFs, manifest.json     (run history, reports)
```

You can try all of this on your laptop with no cloud account: see the [Quickstart](quickstart.md).

## What happens in one run

`sigcomply check` runs these stages in order.

1. Plan. The CLI reads `.sigcomply.yaml`, works out the audit period from the current UTC time,
   picks the policies to evaluate (all of them, or with `--scheduled` the ones that are due),
   and binds each policy to the configured sources that can feed it.
2. Collect. Each source reads its provider's API and returns evidence records. The CLI checks
   every record against the schema of its evidence type, then signs the records and writes them
   to the vault. If a source fails or returns a record that doesn't match its schema, the policy
   that needed it gets the status `error`.
3. Evaluate. Each policy runs against the records it was bound to and gets a status: pass,
   fail, skip, error, not applicable, waived, or carried forward from an earlier run.
4. Write results. The CLI writes each policy's `result.json`, a `summary.json`, and a signed
   `manifest.json` that lists the SHA-256 hash of every file in the run.
5. Submit (optional). If the dashboard is turned on, the CLI sends counts to it.
6. Exit. The exit code tells CI what happened.

The exit code fails the CI job when a policy fails ([exit codes](reference/commands.md#exit-codes)).

## Automated evidence

Credentials stay in your pipeline: an AWS role the job assumes through OIDC, or secrets stored
in your CI. SigComply never receives them.

Sources only read, except that `aws.iam` asks AWS to generate the IAM credential report.
[Sources](reference/sources.md) lists every API action each one calls.

Each source turns the provider's responses into normalized evidence records of a named type. The
vault stores those records, not the provider's responses as returned. Because policies ask for
evidence types rather than named sources, one policy works with any source that emits the type
([Concepts](concepts.md#policies-and-sources-meet-through-evidence-types)).

A policy that no configured source can feed is skipped. A skipped policy is left out of the
compliance score, so a missing source raises the score instead of lowering it. `check` lists every
skipped policy and the evidence type it needs.
[Concepts](concepts.md#what-the-score-does-not-tell-you) explains this in detail.

## Manual evidence

Some controls have no API to ask: a signed NDA policy, a business continuity plan, a training
record. The framework's catalog lists one entry per document the auditor expects. You put the
files for an entry in a folder named after the entry and its period:

```
<prefix><catalog_id>/<period>/
manual/business_continuity_plan/2026/       # annual entry
manual/access_review_quarterly/2026-Q4/     # quarterly entry
```

The default prefix is `manual/`, in the storage configured for the `manual.pdf` source. Each
entry has its own period, such as a calendar year for annual entries or a quarter for quarterly
ones, and you upload within that period
([Upload the files](guides/manual-evidence.md#3-upload-the-files)).

For each entry, the CLI checks that the right files are in the folder for the period, merges them
into one PDF and signs a record of their hashes. The merged PDF goes into the vault next to the
record. [Concepts](concepts.md#the-two-evidence-flows) lists the exact checks.

The CLI never reads or judges what a document says. A policy passes when the right files are in
the right folder at the right time. Whether the content meets the control is your auditor's
decision.

To see which folders are still empty, run `sigcomply evidence due`. For entries that are a form,
the [Evidence SPA](https://sigcomply.github.io/sigcomply-evidence-spa/) turns your answers into a
PDF in your browser. It uploads nothing; you put the PDF in the folder yourself.
[Manual evidence](guides/manual-evidence.md) has the details.

## Signing and verification

The CLI signs each evidence file with Ed25519, using a new key pair for every signature, and
keeps the public key and the signature inside the file. Each run also writes a signed
`manifest.json` with the SHA-256 hash of every file in the run.

You can verify evidence two ways:

- `sigcomply report --period 2026-Q4 --view integrity` re-hashes every file in the period's runs
  and checks each manifest signature. It also flags files that are missing or that the manifest
  doesn't list.
- The [`/verify` page](https://sigcomply.github.io/sigcomply-evidence-spa/verify) checks one
  envelope, and its merged PDF for a manual policy, in your browser. Nothing is uploaded.

What this proves: a file changed or removed after the run fails verification.

What it does not prove: who signed the file. The public key travels in the file, so anyone with
write access to your bucket can replace a file and sign it again with a new key, and the result
looks like an original. To protect evidence against deliberate changes, make the bucket
write-once (for example S3 Object Lock). The CLI doesn't configure that for you.
[Limits of the signatures](concepts.md#limits-of-the-signatures) and [SECURITY.md](../SECURITY.md)
have the details.

## What leaves your pipeline

Nothing leaves your pipeline unless a cloud URL is set (`cloud.base_url` or `--cloud-url`) and
`cloud.project_id` is set. Even then, only full runs in CI (or with `--cloud`) submit, never pull
or merge request pipelines ([Commands](reference/commands.md#sigcomply-check) has the exact rule).

| Sent to the SigComply dashboard | Stays in your pipeline and bucket |
|---|---|
| Each policy's ID, controls, status and counts (resources evaluated, resources failed) | Evidence records and envelopes |
| Run summary counts and compliance score | Uploaded documents and merged PDFs |
| Framework and period | File hashes and signatures |
| Repository, branch, commit and commit time | Names, emails, usernames, ARNs and account IDs |
| CLI version and a link to the CI run | Each run's `manifest.json` and `result.json` |
| | Your credentials |

The `SubmissionPayload` type in [`internal/core/cloud.go`](../internal/core/cloud.go) is the
exact field list. It has no free-form fields and no list of failing resources, and a test fails
the build if one is added. To see what a run would send without sending it, run
`sigcomply check --capture-cloud-payload payload.json`.

## The SigComply dashboard

The dashboard works only from the counts above. It adds run history, reports over your audit
window and an auditor portal; [Cloud dashboard](guides/cloud-dashboard.md) lists what each plan
includes.

The ISO 27001 Statement of Applicability doesn't need SigComply Cloud: the CLI produces it for
free with `sigcomply report --view soa`.

## Further reading

- [Concepts](concepts.md): what SigComply doesn't do, the evidence flows, how policies bind to
  sources, the limits of the signatures and the score.
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
