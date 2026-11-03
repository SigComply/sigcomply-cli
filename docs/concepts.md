# Concepts

This page explains the model behind a SigComply result, for auditors and reviewers. For one run
from start to finish, see [How SigComply works](how-it-works.md).

## What SigComply does not do

- It does not run vendor security reviews, security awareness training, device monitoring or
  background checks, and it does not host a trust center. It checks that the documents these
  produce are on file.
- It does not decide whether you are compliant, and it does not certify anything. It collects
  evidence and evaluates policies; your auditor decides.
- It does not read or judge uploaded documents. A manual policy passes when a supported file is
  in the right folder for the period, whatever the file says.
- The vault keeps each run, but the CLI doesn't compare runs; full history and trends are
  SigComply Cloud features.
- It does not change your infrastructure. Sources make read-only API calls.
- It does not configure your storage. Write-once retention on the evidence bucket is your
  setting (see [Limits of the signatures](#limits-of-the-signatures)).

## The two evidence flows

Every policy declares one of two evidence modes in `evidence_mode`.

Automated policies (`evidence_mode: automated`) read records that a source collects from a
provider API with your credentials. Each record is checked against a versioned schema for its
evidence type, then the policy's condition is evaluated. Example: every IAM user has MFA enabled.

Manual policies (`evidence_mode: manual`) read documents you upload, such as a signed NDA, an
access review export or a training certificate. The CLI lists the entry's folder in your bucket,
converts images to PDF and merges the files into one PDF. The policy passes when:

- a supported file is in the folder,
- the latest file was uploaded within the entry's own period (for example the year 2026 for an
  annual entry; see [Upload the files](guides/manual-evidence.md#3-upload-the-files)),
- the files are not byte-identical to the previous period's,
- the merged file looks like a valid PDF.

The CLI does not extract text or check signatures inside the document. Reviewing what a document
says is the auditor's job.

## Policies and sources meet through evidence types

A policy never names a source, and a source never names a policy. A policy declares the
evidence types each of its slots accepts. A source declares the evidence types it emits. The
planner binds a source to a slot when the two lists overlap.

So one "MFA enforced for all users" policy works with AWS IAM, Okta, Microsoft Entra ID or
Google Workspace, because each of their sources emits the `directory_user` type. A source
you build yourself with `sigcomply build` works the same way if it emits that type.

A slot that no configured source can fill makes the policy skip.

## What leaves your environment

```
Sent to the dashboard:   3 of 40 users failed soc2.cc6.1.mfa_enforced_all_users
Never sent:              "alice, bob and carol have MFA disabled"
```

To see which resources failed, read `result.json` in your own vault.
[What leaves your pipeline](how-it-works.md#what-leaves-your-pipeline) lists what is sent and
what stays.

## Signing and the vault

`check` writes each run to your vault: a local folder, S3, GCS or Azure Blob. For each evidence
file it writes a signed envelope. The signature covers the canonical JSON of the envelope's
format version, production time and records.

Each envelope is signed with a new Ed25519 key pair. The CLI discards the private key right after
signing and stores the public key and signature in the envelope, so anyone can verify a single
file on its own.

Each run also writes `manifest.json`: the SHA-256 hash of every file in the run, signed with its
own one-time key. One check of the manifest covers the whole run.

For manual evidence, the envelope records the SHA-256 hash of each uploaded source file and of
the merged PDF. The merged PDF is written to the run folder, so the manifest covers it too.

[Verify evidence](guides/verify-evidence.md) shows both ways to check a run.

### Limits of the signatures

The signatures detect accidental corruption and a file changed after the run. They do not stop
someone with write access to the vault from creating a new envelope with a new key pair: since
the public key lives in the envelope, the result looks like an original. Runs are not chained to
each other either. The CLI also signs whatever it reads, so it cannot tell a fabricated document
from a genuine one.

Protection against deliberate changes comes from write-once storage, which you configure: S3
Object Lock (or versioning with MFA delete), GCS Bucket Lock or retention policies, or Azure
immutable blob storage. A local vault has none of this. The full threat model is in
[SECURITY.md](../SECURITY.md).

## What the score does not tell you

The compliance score is (passed + waived + carried forward) / (total - skipped - not
applicable). Two things can make it look better than the estate is.

Skipped policies leave the denominator. A policy skips in two cases: no configured source emits
the evidence it needs, or a configured source returned no records for a policy about every
resource of a kind. So forgetting to configure a source raises the score instead of lowering it.
A policy that asks whether a service exists at all, such as audit logging, fails rather than
skips when the source finds none.

`check` lists every skipped policy and the evidence it needs, and `sigcomply report --view scope`
shows what a run did not evaluate. To make a missing source fail the run, declare the sources
you expect under `experimental.scope`; see [Configuration](configuration.md).

A pass can examine nothing. A rule such as "every bucket is encrypted" is true when there are no
buckets. When a policy passes without matching any resource, `check` says
`passed without examining any resource`, and the dashboard receives the flag `vacuous`.

The score also counts a control backed by a document on file the same as one verified against
live configuration. And an automated check shows that something is configured, not that it was
exercised: a backup that is enabled is not a restore that was tested.
`sigcomply report --view coverage` shows which kind of check stands behind each control.

## See also

- [How SigComply works](how-it-works.md): one run from start to finish, and what leaves your
  pipeline.
- [Frameworks](reference/frameworks.md): shipped frameworks and their counts.
- [Verify evidence](guides/verify-evidence.md): report views and the `/verify` page.
- [ARCHITECTURE.md](../ARCHITECTURE.md): the system design, for contributors.
