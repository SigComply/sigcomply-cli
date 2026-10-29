# Run SigComply in CI

In this tutorial you take a SigComply project into CI. It assumes you ran the
[Quickstart](quickstart.md); you start again in your repository. By the end,
SigComply runs on a schedule, stores signed evidence in a bucket you own, and, if you choose,
sends counts to the SigComply Cloud dashboard. The examples use AWS and GitHub Actions; GitLab
differences are noted where they apply.

## Before you start

You need:

- A GitHub or GitLab repository for this project. One repository holds one framework.
- The `sigcomply` CLI installed locally ([Install](guides/install.md)).
- An AWS account where you can create an IAM role and an S3 bucket.
- For the dashboard only: a SigComply Cloud account on the paid plan or in its free trial. The
  first submission from a new organization starts the trial.

## 1. Commit a config

In the root of the repository, scaffold the config if you haven't already, then edit it:

```sh
sigcomply init -f soc2
```

Change two things in `.sigcomply.yaml`:

1. Under `sources:`, list every source you want evidence from. The CLI only reads sources you
   list here; having credentials isn't enough. Per-source keys and permissions are in
   [Sources](reference/sources.md).
2. Point `vault:` and `manual.pdf` at a bucket instead of local folders, so evidence survives
   the CI job:

   ```yaml
   sources:
     aws.iam:
       region: us-east-1
     manual.pdf:
       backend: s3
       bucket: <your-evidence-bucket>
       region: us-east-1
       prefix: manual/

   vault:
     backend: s3
     bucket: <your-evidence-bucket>
     region: us-east-1
     prefix: sigcomply/
   ```

   For evidence an auditor relies on, turn on S3 Object Lock or versioning on that bucket.
   [Concepts](concepts.md#limits-of-the-signatures) explains why.

Commit the file.

## 2. Turn on cloud submission (dashboard users only)

Skip this step if you don't use SigComply Cloud. The CLI then keeps everything in your bucket
and sends nothing.

1. Sign up at [sigcomply.com](https://sigcomply.com) and connect the repository by its URL. See
   [Cloud dashboard](guides/cloud-dashboard.md).
2. Copy the **Project ID** from the project's page on the dashboard.
3. Add this block to `.sigcomply.yaml`, with your Project ID, and commit it:

   ```yaml
   cloud:
     base_url: https://sigcomply.com
     project_id: prj_7Xq2mKp9RtV4wNc8Bz3a   # your Project ID
   ```

The base URL is `https://sigcomply.com`. The OIDC audience you meet in step 4,
`https://api.sigcomply.com`, is a fixed identifier, not a web address, so the two differ on
purpose.

Without `cloud.base_url`, the CLI never submits, even in CI. With it, the CLI submits when it
runs in GitHub Actions or GitLab CI and can get an OIDC token. No API key or secret is involved.
The project ID is not a secret: it tells SigComply Cloud which project the runs belong to. With a
cloud URL and no `cloud.project_id`, `check` warns and keeps running; the next release will make
that a config error.

## 3. Scaffold the CI workflows

For GitHub Actions:

```sh
sigcomply init-ci --ci github
```

This writes two workflows to `.github/workflows/`. `compliance-scheduled.yml` runs
`sigcomply check --scheduled` every day at 02:00 UTC: it evaluates the policies that are due and
carries the rest forward, so each run covers every policy. It also runs
`sigcomply evidence due --within-days 30`, which lists documents still missing whose period ends
within 30 days and never fails the job. `compliance-on-push.yml` runs `sigcomply check --pr` on
pull requests and pushes to `main`.

For GitLab CI, run `sigcomply init-ci --ci gitlab`. It writes one `.gitlab-ci.yml`; you then
create one daily pipeline schedule. See [CI on GitLab](guides/ci-gitlab.md).

`init-ci` scaffolds SOC 2 only. For another framework, see
[Commands](reference/commands.md#sigcomply-init-ci).

## 4. Let CI assume an AWS role

The workflows get AWS credentials through OIDC, not stored keys. Each workflow requests an OIDC
token with the audience `https://api.sigcomply.com` and uses it for both AWS and SigComply
Cloud. In AWS:

1. Create an IAM OIDC identity provider for your CI host (`token.actions.githubusercontent.com`
   for GitHub Actions, your GitLab host such as `gitlab.com` for GitLab CI) and add
   `https://api.sigcomply.com` as its audience. The AWS default
   audience `sts.amazonaws.com` does not match the token the workflows request.
2. Create a role that this provider can assume, limited to your repository, with read-only
   access (for example `ReadOnlyAccess`) and write access to the evidence bucket.
3. Replace the `AWS_ROLE_ARN` placeholder (`arn:aws:iam::000000000000:role/REPLACE_ME`) in each
   scaffolded workflow with the role's ARN.

[CI on GitHub](guides/ci-github.md) and [CI on GitLab](guides/ci-gitlab.md) have the trust
policy and the full setup.

## 5. Run it

Commit the workflows and push. Then start the scheduled workflow by hand from the **Actions**
tab (it has a `workflow_dispatch` trigger), or wait for its schedule.

The first scheduled run evaluates every policy. In the job log, `check` prints a summary line
with the framework and the period, then one line per policy. The job fails (exit `1`) while any of those policies fails. To keep
the job green on failing policies, set `ci.fail_on_violation: false` in `.sigcomply.yaml`. Exit
codes are listed in [Commands](reference/commands.md#exit-codes).

Document policies are part of every scheduled run. Until a document is uploaded for the
current period, its policy fails, and it is checked again on each daily run. Once it passes, it
carries forward until its cadence (annual or quarterly in the shipped catalogs) comes due again.

If you turned on cloud submission, the run appears on the dashboard. The first submission from
a new organization starts its trial; see [Cloud dashboard](guides/cloud-dashboard.md).

## 6. Upload manual evidence

Policies, training records and reviews come from documents you upload to the `manual.pdf`
bucket. To see what is missing and where each file goes, run this locally with credentials that
can list the bucket:

```sh
sigcomply evidence due --all
```

Each row names a folder such as `s3://<your-evidence-bucket>/manual/nda_policy/2026/`. Upload
one or more PDF or image files there during the period. The next scheduled run checks that a
file is present for the period, merges the files into one PDF to validate them, and signs a
record of each file's hash. It does not read the content. Start the scheduled workflow by hand to
see the result right away.

[Manual evidence](guides/manual-evidence.md) covers folder names, file formats, the Evidence
SPA form helper and upload windows.

## Next steps

- [Verify evidence](guides/verify-evidence.md): check signatures and coverage with
  `sigcomply report`.
- [Identity roster](guides/identity-roster.md): check every system's accounts against your list
  of people.
- [Troubleshooting](guides/troubleshooting.md): common errors and what they mean.
