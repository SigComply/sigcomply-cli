# Run SigComply in GitLab CI

Add SigComply jobs to a GitLab project and run them from a daily pipeline schedule. The jobs get
AWS credentials from GitLab ID tokens, so you store no AWS keys.

## Prerequisites

- A project on GitLab with a working `.sigcomply.yaml` ([Add an evidence source](configure-sources.md)).
- The CLI installed on your machine ([install guide](install.md)).
- Maintainer access to the GitLab project, to create pipeline schedules.
- For AWS sources: permission to create an IAM OIDC identity provider and IAM roles in each AWS
  account you collect from.
- A `vault:` and a `manual.pdf` source that point at buckets, not local paths. A CI job's local
  folder disappears when the job ends. Keys: [configuration reference](../configuration.md) and
  [Upload manual evidence](manual-evidence.md#1-configure-the-manual-evidence-source).
- A masked CI/CD variable for each GitHub, GitLab, Okta or Active Directory source:
  [Supply credentials in CI](configure-sources.md#supply-github-gitlab-okta-and-active-directory-credentials-in-ci).

## 1. Scaffold the pipeline

From the repository root:

```bash
sigcomply init-ci --ci gitlab
```

If `.gitlab-ci.yml` already exists, `init-ci` stops with exit `3`; pass `--force` to replace it.
It writes `.gitlab-ci.yml` with a hidden base job, `.sigcomply_base`, and two jobs that extend it:

| Job | Runs when | Command |
|---|---|---|
| `compliance:scheduled` | Any scheduled pipeline | `sigcomply check --scheduled`, then `sigcomply evidence due --within-days 30` |
| `compliance:on_push` | Every merge request, and pushes to the default branch | `sigcomply check --pr` |

The scheduled job evaluates the policies whose cadence has come due, or that failed last time,
and carries the rest forward from the state in the vault. A daily run evaluates each policy at
least once in every window of its cadence. Only this job sends results to the dashboard and
updates the state, which is why the vault must be a bucket.

The `--pr` job evaluates the policies marked `on_push`: every automated policy in the shipped
frameworks. The `evidence due` step lists empty manual-evidence folders whose period ends within
30 days, and never fails the job.

For ISO 27001, keep `framework: iso27001` in `.sigcomply.yaml` and run
`sigcomply init-ci --ci gitlab --framework soc2`. The jobs read the framework from the config, and
`init-ci` accepts only `soc2`: without the flag it reads `iso27001` from the config and exits `3`.

## 2. Pin the CLI version

In the `variables:` block at the top of `.gitlab-ci.yml`, or as project CI/CD variables, set:

| Variable | Set to |
|---|---|
| `SIGCOMPLY_VERSION` | A release tag. A release build of the CLI writes its own version here; a build from source writes `latest`. Bump it when you upgrade. |
| `AWS_REGION` | The region of your AWS sources. |

The base job checks the downloaded archive against the release's `checksums.txt`. The build
provenance check ships commented out, because the `ubuntu:24.04` image has no GitHub CLI. To turn
it on, install `git` and a recent `gh` in the image and uncomment the `gh attestation verify`
lines. Step 3 of
[Install a release archive by hand](install.md#install-a-release-archive-by-hand) explains it.

## 3. Create the AWS OIDC provider and roles

Skip this step if you collect nothing from AWS, and set `SIGCOMPLY_SCHEDULED_ROLE_ARN` and
`SIGCOMPLY_ON_PUSH_ROLE_ARN` to `""` so the AWS SDK doesn't try to assume the placeholder role.

The base job mints two ID tokens, one per receiver:

- `AWS_ID_TOKEN`, with the audience `sts.amazonaws.com`. The job writes it to a file and exports
  `AWS_WEB_IDENTITY_TOKEN_FILE`, so the AWS SDK inside the CLI assumes the role in
  `AWS_ROLE_ARN`. Each job sets `AWS_ROLE_ARN` from its own role variable.
- `SIGCOMPLY_ID_TOKEN`, with the audience `https://api.sigcomply.com`. The CLI sends it only to
  SigComply.

Never let an AWS role trust `https://api.sigcomply.com`: SigComply receives every token with that
audience, so such a role would trust tokens that leave your CI. For self-managed GitLab, replace
`gitlab.com` below with your instance's host.

Each job assumes its own role:

| Role | Used by | Trusts | Writes to the vault |
|---|---|---|---|
| Scheduled role | `compliance:scheduled` | the default branch only (`main` below) | run folders and the cadence state in `state/` |
| On-push role | `compliance:on_push` | every branch, since merge requests run from theirs | run folders only, never `state/` |

A merge request pipeline runs the branch's `.gitlab-ci.yml`, so anyone who can push a branch
controls what the on-push role does. That role can't write `state/`, so a branch can't change
what the next scheduled run carries forward.

1. Create the provider. If the account already has a provider for `https://gitlab.com` with the
   client ID `sts.amazonaws.com`, reuse it.

   ```bash
   aws iam create-open-id-connect-provider \
     --url https://gitlab.com \
     --client-id-list sts.amazonaws.com
   ```

2. Create the scheduled role with this trust policy. Replace the account ID and
   `my-group/my-project`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "SigComplyScheduled",
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::111122223333:oidc-provider/gitlab.com"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "gitlab.com:aud": "sts.amazonaws.com",
             "gitlab.com:sub": "project_path:my-group/my-project:ref_type:branch:ref:main"
           }
         }
       }
     ]
   }
   ```

   Protect `main` (**Settings > Repository > Protected branches**), so only maintainers can push
   to it and run pipelines on it with this role.

3. Create the on-push role with this trust policy:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "SigComplyOnPush",
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::111122223333:oidc-provider/gitlab.com"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "gitlab.com:aud": "sts.amazonaws.com"
           },
           "StringLike": {
             "gitlab.com:sub": "project_path:my-group/my-project:*"
           }
         }
       }
     ]
   }
   ```

4. Attach permissions to both roles: the AWS managed policies `SecurityAudit` and
   `ViewOnlyAccess`, or the per-source permissions in the
   [sources reference](../reference/sources.md#aws). If the vault is in S3, add an inline policy
   for the buckets. Replace the bucket names:

   - Scheduled role: read the manual-evidence bucket, and read and write the vault.

     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": ["s3:GetObject", "s3:ListBucket"],
           "Resource": ["arn:aws:s3:::my-evidence-bucket", "arn:aws:s3:::my-evidence-bucket/*"]
         },
         {
           "Effect": "Allow",
           "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
           "Resource": ["arn:aws:s3:::my-vault-bucket", "arn:aws:s3:::my-vault-bucket/*"]
         }
       ]
     }
     ```

   - On-push role: add run folders to the vault, but not `state/`. A `--pr` run skips document
     policies, so it needs no access to the manual-evidence bucket. If you set `vault.prefix`,
     put it in front of `state/`.

     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": ["s3:PutObject", "s3:ListBucket"],
           "Resource": ["arn:aws:s3:::my-vault-bucket", "arn:aws:s3:::my-vault-bucket/*"]
         },
         {
           "Effect": "Deny",
           "Action": "s3:PutObject",
           "Resource": "arn:aws:s3:::my-vault-bucket/state/*"
         }
       ]
     }
     ```

   If a bucket uses a customer managed KMS key, also allow `kms:Decrypt` (reads) and
   `kms:GenerateDataKey` (writes) on that key.

5. In `.gitlab-ci.yml` or as CI/CD variables, set `SIGCOMPLY_SCHEDULED_ROLE_ARN` to the scheduled
   role's ARN and `SIGCOMPLY_ON_PUSH_ROLE_ARN` to the on-push role's ARN.

If a role you created earlier trusts `https://api.sigcomply.com`, fix it:
[Troubleshooting](troubleshooting.md#an-aws-role-trusts-httpsapisigcomplycom).

## 4. Create a daily pipeline schedule

`compliance:scheduled` runs only in scheduled pipelines. In your project:

1. Go to **Build > Pipeline schedules > New schedule**.
2. Enter a daily interval pattern, for example `0 2 * * *` (02:00 UTC).
3. Save. One schedule is enough: each run decides which policies are due.

## 5. Optional: send results to the SigComply dashboard

Connect the repository in the dashboard and copy its **Project ID**:
[Connect to the SigComply dashboard](cloud-dashboard.md). Then add this to `.sigcomply.yaml`:

```yaml
cloud:
  base_url: https://sigcomply.com
  project_id: prj_7Xq2mKp9RtV4wNc8Bz3a   # the Project ID from your project's page
```

Without `cloud.base_url`, the CLI sends nothing. Without `cloud.project_id`, a scheduled run stops
with exit `3` before it collects anything.

## 6. Commit and run

The scheduled job fails (exit `1`) until every document policy has a file for the current period.
To keep the job green while you upload them, set `ci.fail_on_violation: false` in
`.sigcomply.yaml` before you push.

```bash
git add .gitlab-ci.yml .sigcomply.yaml
git commit -m "ci: add SigComply compliance pipeline"
git push
```

## Verify

1. The push runs `compliance:on_push` on the default branch. Open it under **Build > Pipelines**.
2. On **Build > Pipeline schedules**, start the schedule with **Run pipeline schedule**.
3. In the `compliance:scheduled` job log, check that collection started for each source and the
   run summary lists every policy of the framework; later runs list the ones not yet due as
   `carried`. Document policies fail until you upload their files. The job fails with exit code
   `1` when a policy fails, `2` on an execution error and `3` on a configuration error
   ([exit codes](../reference/commands.md#exit-codes)).
4. If you set `cloud.base_url`, the scheduled job's log shows `submission accepted (HTTP 201)` or
   a `submit:` warning ([Troubleshooting](troubleshooting.md#cloud-submission)).

## Next steps

- [`examples/gitlab-ci.yml`](../../examples/gitlab-ci.yml): the same pipeline with
  `SIGCOMPLY_VERSION: latest`.
- [Connect to the SigComply dashboard](cloud-dashboard.md).
- [Upload manual evidence](manual-evidence.md).
- [Verify evidence](verify-evidence.md).
