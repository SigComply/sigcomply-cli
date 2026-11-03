# Run SigComply in CI

Take SigComply from your laptop into CI. By the end, it runs every day in your repository's
pipeline and writes signed evidence to an S3 bucket you own. You can also send counts to the
SigComply dashboard. The examples use AWS and GitHub Actions; GitLab differences are noted where
they apply. Work in the repository you want to check, not the [Quickstart](quickstart.md) folder.

## Before you start

You need:

- A GitHub or GitLab repository for this project. Each repository checks one framework.
- The `sigcomply` CLI installed locally ([Install](guides/install.md)).
- An AWS account where you can create an IAM role and an S3 bucket.
- For the optional dashboard only: an account at [sigcomply.com](https://sigcomply.com).

## 1. Create an evidence bucket

For evidence an auditor relies on, turn on S3 Object Lock, or versioning with MFA delete, before
you store evidence in the bucket. Without it, anyone who can write to the bucket can replace a
signed file and sign it again ([Limits of the signatures](concepts.md#limits-of-the-signatures)).

Create the bucket in the AWS console or with:

```sh
aws s3 mb s3://<your-evidence-bucket> --region us-east-1
```

## 2. Commit a config

In the root of the repository, scaffold the config if you haven't already, then edit it:

```sh
sigcomply init -f soc2
```

Change two things in `.sigcomply.yaml`:

1. Under `sources:`, list every source you want evidence from. The CLI only reads sources you
   list here; having credentials isn't enough. Per-source keys and permissions are in
   [Sources](reference/sources.md).
2. Point `vault:` and `manual.pdf` at the bucket instead of local folders, so evidence survives
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

Commit the file.

## 3. Scaffold the CI workflows

For GitHub Actions:

```sh
sigcomply init-ci --ci github
```

This writes two workflows to `.github/workflows/`. `compliance-scheduled.yml` runs
`sigcomply check --scheduled` every day at 02:00 UTC. It evaluates the policies that are due and
carries the rest forward, so each run covers every policy. `compliance-on-push.yml` runs
`sigcomply check --pr` on pull requests and pushes to `main`.
[CI on GitHub](guides/ci-github.md) describes both workflows.

For GitLab CI, run `sigcomply init-ci --ci gitlab`. It writes one `.gitlab-ci.yml`; you then
create one daily pipeline schedule. See [CI on GitLab](guides/ci-gitlab.md).

`init-ci` scaffolds SOC 2 only. For another framework, see
[Commands](reference/commands.md#sigcomply-init-ci).

## 4. Let CI assume an AWS role

The workflows get AWS credentials through OIDC, not stored keys. AWS gets its own OIDC token,
with the audience `sts.amazonaws.com`; the token for the SigComply dashboard has the audience
`https://api.sigcomply.com`, and no AWS role may trust that one. In AWS:

1. Create an IAM OIDC identity provider for your CI host (`token.actions.githubusercontent.com`
   for GitHub Actions, your GitLab host such as `gitlab.com` for GitLab CI) with the audience
   `sts.amazonaws.com`.
2. Create two roles that this provider can assume. The scheduled role trusts only your default
   branch and writes the vault. The on-push role trusts pull or merge requests and can't write
   the vault's `state/`. Give both the AWS managed policies `SecurityAudit` and `ViewOnlyAccess`,
   plus access to the evidence buckets.
3. Replace the role placeholders (`arn:aws:iam::000000000000:role/REPLACE_ME`) with the roles'
   ARNs, and set `AWS_REGION` to your region. On GitHub, each workflow has its own
   `AWS_ROLE_ARN`. On GitLab, they are `SIGCOMPLY_SCHEDULED_ROLE_ARN` and
   `SIGCOMPLY_ON_PUSH_ROLE_ARN` in the `variables:` block of `.gitlab-ci.yml`.

[CI on GitHub](guides/ci-github.md) and [CI on GitLab](guides/ci-gitlab.md) have the trust
policies, the bucket permissions and the full setup.

## 5. Run it

The first scheduled run evaluates every policy, and the job fails (exit `1`) while any policy
fails. On a new project that includes every document policy until its document is uploaded. To
keep the job green meanwhile, set `ci.fail_on_violation: false` in `.sigcomply.yaml` before you
push. Exit codes are listed in [Commands](reference/commands.md#exit-codes).

Commit the workflows and push. Then start the scheduled workflow by hand from the **Actions**
tab (it has a `workflow_dispatch` trigger), or wait for its schedule.

In the job log, `check` prints a summary line with the framework and the period, then one line
per policy. A document policy fails until its document is uploaded for the current period, and
each daily run checks it again. Once it passes, it carries forward until its cadence (annual or
quarterly in the shipped catalogs) comes due again.

## 6. Upload manual evidence

Policies, training records and reviews come from documents you upload to the `manual.pdf`
bucket. To see what is missing and where each file goes, run this locally with credentials that
can list the bucket:

```sh
sigcomply evidence due --all
```

Each row names a folder such as `s3://<your-evidence-bucket>/manual/nda_policy/2026/`. Upload
one or more PDF or image files there during the period. The next scheduled run picks them up;
start the scheduled workflow by hand to see the result right away.

[Manual evidence](guides/manual-evidence.md) covers folder names, file formats, the Evidence
SPA form helper and upload windows.

## 7. Optional: send counts to the SigComply dashboard

Without this step, the CLI keeps everything in your bucket and sends nothing.

1. Sign up at [sigcomply.com](https://sigcomply.com) and connect the repository by its URL. See
   [Cloud dashboard](guides/cloud-dashboard.md).
2. Copy the **Project ID** from the project's page on the dashboard.
3. Add this block to `.sigcomply.yaml`, with your Project ID, and commit it:

   ```yaml
   cloud:
     base_url: https://sigcomply.com
     project_id: prj_7Xq2mKp9RtV4wNc8Bz3a   # your Project ID
   ```

In CI the CLI signs in with the pipeline's OIDC token, so you add no API key or secret. The
Project ID isn't a secret. Only the scheduled run sends counts. The next one appears on the
dashboard, and your organization's first submitted run starts its SigComply Cloud trial.
[Cloud dashboard](guides/cloud-dashboard.md) has the rules and the plan details.

## Next steps

- [Verify evidence](guides/verify-evidence.md): check signatures and coverage with
  `sigcomply report`.
- [Identity roster](guides/identity-roster.md): check every system's accounts against your list
  of people.
- [Troubleshooting](guides/troubleshooting.md): common errors and what they mean.
