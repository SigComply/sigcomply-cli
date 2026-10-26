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
- For the dashboard only: a SigComply Cloud account. The first submission from a new
  organization starts a trial.

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
2. Add this block to `.sigcomply.yaml` and commit it:

   ```yaml
   cloud:
     base_url: https://sigcomply.com
   ```

The base URL is `https://sigcomply.com`. The OIDC audience you meet in step 4,
`https://api.sigcomply.com`, is a fixed identifier, not a web address, so the two differ on
purpose.

Without `cloud.base_url`, the CLI never submits, even in CI. With it, the CLI submits when it
runs in GitHub Actions or GitLab CI and can get an OIDC token. No API key or secret is involved.

## 3. Scaffold the CI workflows

For GitHub Actions:

```sh
sigcomply init-ci --ci github
```

This writes six workflows to `.github/workflows/`: one each for the daily, weekly, monthly,
quarterly and annual checks, and `compliance-on-push.yml`. The daily workflow also runs
`sigcomply evidence due`, which lists missing documents and never fails the job.

For GitLab CI, run `sigcomply init-ci --ci gitlab`. It writes one `.gitlab-ci.yml`; you then
create a pipeline schedule per cadence. See [CI on GitLab](guides/ci-gitlab.md).

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

Commit the workflows and push. Then start the daily workflow by hand from the **Actions** tab
(it has a `workflow_dispatch` trigger), or wait for its schedule.

In the job log, `check` prints the same summary you saw in the Quickstart. The job fails
(exit `1`) while any policy fails; that is expected until the documents are uploaded. To keep
the job green on failing policies, set `ci.fail_on_violation: false` in `.sigcomply.yaml`. Exit codes are listed in
[Commands](reference/commands.md#exit-codes).

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
one or more PDF or image files there. The workflow for the entry's cadence (the `CADENCE`
column) checks that a file is present for the period, merges the files into one PDF and signs
the result. It does not read the content. An annual document waits for the annual workflow, so
start that workflow by hand to see the result right away.

[Manual evidence](guides/manual-evidence.md) covers folder names, file formats, the Evidence
SPA form helper and upload windows.

## Next steps

- [Verify evidence](guides/verify-evidence.md): check signatures and coverage with
  `sigcomply report`.
- [Identity roster](guides/identity-roster.md): check every system's accounts against your list
  of people.
- [Troubleshooting](guides/troubleshooting.md): common errors and what they mean.
