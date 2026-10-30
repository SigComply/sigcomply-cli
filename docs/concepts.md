# Concepts

SigComply is a compliance engine and evidence collector that runs in your own CI. The
`sigcomply` CLI uses your read-only credentials to pull configuration from AWS, GCP, Azure,
GitHub, GitLab, Okta and Active Directory, and evaluates it against SOC 2 and ISO 27001 policies
you can read in the source. For controls no API can answer, it collects the documents you
upload. Raw evidence and results stay in storage you own. With SigComply Cloud (paid, with a
2-month free trial), the CLI also sends pass/fail counts per policy to a dashboard.

The design goal is evidence without access: the vendor never holds your credentials, your
infrastructure data or the identities in it. Your raw evidence stays in your own storage.

## What SigComply does not do

- It does not decide whether you are compliant, and it does not certify anything. It collects
  evidence and evaluates policies; your auditor decides.
- It does not read or judge uploaded documents. A manual policy passes when a supported file is
  in the right folder for the period, whatever the file says.
- It does not keep a history of results. The vault holds each run's evidence, and the CLI keeps
  only the scheduling state it needs for cadences. That state lives under `state/` in the vault,
  so a CI runner with a fresh disk still finds it when the vault is a bucket. Trends and drift over time are SigComply
  Cloud features.
- It does not change your infrastructure. Sources make read-only API calls.
- It does not configure your storage. Write-once retention on the evidence bucket is your
  setting (see [Limits of the signatures](#limits-of-the-signatures)).

## The two evidence flows

Every policy declares one of two evidence modes in `evidence_mode`.

Automated policies (`evidence_mode: automated`) read records that a source collects from a
provider API with your credentials. Each record is checked against a versioned schema for its
evidence type, then the policy's `pass_when` condition is evaluated. Example: every IAM user has
MFA enabled.

Manual policies (`evidence_mode: manual`) read documents you upload, such as a signed NDA, an
access review export or a training certificate. The CLI lists the policy's folder in your
bucket, converts images to PDF, merges the files into one PDF, and checks three things: that a
supported file is present, that the merged file looks like a valid PDF, and that it was
uploaded within the entry's own period (for example the year 2026 for an annual entry) plus its
grace period. It also fails a folder whose files are byte-identical to the previous period's. It
does not extract text or check signatures inside the document. Reviewing what a document says
is the auditor's job.

There are only these two flows. The catalog's `type` values (`document_upload`, `declaration`,
`checklist`) tell the optional [Evidence SPA](guides/manual-evidence.md) which entries it can
render as a form; the CLI ignores them.

## Policies and sources meet through evidence types

A policy never names a source, and a source never names a policy. A policy declares the
evidence types each of its slots accepts. A source declares the evidence types it emits. The
planner binds a source to a slot when the two lists overlap.

So one "MFA enforced for all users" policy works with AWS IAM, Okta, Microsoft Entra ID or
Google Workspace, because each of their sources emits the `directory_user` type. A source
you build yourself with `sigcomply build` works the same way if it emits that type.

Most policies have one slot, named `evidence`. Identity-roster policies have `roster` and
`accounts`, and change-management policies have `changes` and `deployments`. A slot that no
configured source can fill makes the policy skip.

## The aggregation boundary

The CLI is the only place raw evidence is reduced to counts.

Stays in your storage: the normalized evidence records that sources build from API responses,
uploaded documents, the full list of failing resources with their identifiers (ARNs, emails,
usernames, account IDs), signatures, and each run's `manifest.json`.

Leaves your environment, only when cloud submission is on: per-policy counts and status, the
run's summary counts and score, and CI metadata (repository, branch, commit, CLI version).

```
Sent to the dashboard:   3 of 40 users failed soc2.cc6.1.mfa_enforced_all_users
Never sent:              "alice, bob and carol have MFA disabled"
```

The submission type has no free-form fields and no list of violations, so it cannot carry an
identifier. To see which resources failed, read `result.json` in your own vault.

Cloud submission is off unless you set `cloud.base_url` in `.sigcomply.yaml` (or pass
`--cloud-url`), and it only happens in CI with an OIDC token. The run also names its project with
`cloud.project_id`, the public Project ID from the dashboard, sent in a header. SigComply Cloud
accepts the run only if that ID and the token's repository name the same project. A run that
would submit without the key stops with exit `3` before it collects anything. See
[Configuration](configuration.md).

## Signing and the vault

`check` writes each run to your vault: a local folder, S3, GCS or Azure Blob. For each evidence
file it writes a signed envelope. The signature covers the canonical JSON of the envelope's
format version, production time and records. Each envelope is signed with a new Ed25519 key
pair; the CLI discards the private key right after signing and stores the public key and
signature in the envelope, so anyone can verify a single file on its own.

Each run also writes `manifest.json`: the SHA-256 hash of every file in the run, signed with its
own one-time key. One check of the manifest covers the whole run.

For manual evidence, the envelope records the SHA-256 hash of each uploaded source file and of
the merged PDF. The merged PDF is written to the run folder, so the manifest covers it too.

You can verify a run with `sigcomply report --view integrity`, or a single envelope in the
browser on the Evidence SPA `/verify` page. See [Verify evidence](guides/verify-evidence.md).

### Limits of the signatures

The signatures detect accidental corruption and a file changed after the run. They do not stop
someone with write access to the vault from creating a new envelope with a new key pair: since
the public key lives in the envelope, the result looks like an original. The CLI also signs
whatever it reads, so it cannot tell a fabricated document from a genuine one.

Protection against deliberate changes comes from write-once storage, which you configure: S3
Object Lock (or versioning with MFA delete), GCS Bucket Lock or retention policies, or Azure
immutable blob storage. A local vault has none of this. The full threat model is in
[SECURITY.md](../SECURITY.md).

## What the score does not tell you

The compliance score is (passed + waived + carried forward) / (total - skipped - not
applicable). Two things can make it look better than the estate is.

Skipped policies leave the denominator. A policy skips in two cases: no configured source emits
the evidence it needs, or a configured source returned no records for a policy about every
resource of a kind ("every bucket is encrypted" says nothing about an account with no buckets).
So forgetting to configure a source raises the score instead of lowering it. A policy that asks
whether a service exists at all (audit logging, threat detection, configuration recording, a
backup plan, security alerting, a SIEM, a password policy) does not skip on an empty source: it
fails with `no <type> records: <service> not enabled or not found`.
`check` lists every skipped policy and the evidence it needs, and `sigcomply report --view scope`
shows what a run did not evaluate. To make a missing source fail the run, declare the sources
you expect under `experimental.scope`; see [Configuration](configuration.md).

A pass can examine nothing. A rule such as "every bucket is encrypted" is true when there are no
buckets. When a policy passes without matching any resource, `check` says
`passed without examining any resource`, and the dashboard receives the flag `vacuous`.

The score also counts a control backed by a document on file the same as one verified against
live configuration, and an automated check shows that something is configured, not that it was
exercised (a backup that is enabled is not a restore that was tested). `sigcomply report --view
coverage` shows which kind of check stands behind each control.

## See also

- [How SigComply works](how-it-works.md): one run from start to finish, and what leaves your
  pipeline.
- [Frameworks](reference/frameworks.md): shipped frameworks and their counts.
- [Verify evidence](guides/verify-evidence.md): report views and the `/verify` page.
- [ARCHITECTURE.md](../ARCHITECTURE.md): the system design, for contributors.
