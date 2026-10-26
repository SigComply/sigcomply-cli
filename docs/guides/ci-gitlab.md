# Run SigComply in GitLab CI

Add SigComply jobs to a GitLab project and drive them with pipeline schedules. The jobs use a
GitLab ID token to assume a read-only AWS role and, if you use the paid dashboard, to
authenticate to SigComply Cloud. You store no long-lived secret.

## Prerequisites

- A project on GitLab with a working `.sigcomply.yaml` ([Add an evidence source](configure-sources.md)).
- The CLI installed on your machine ([install guide](install.md)).
- Maintainer access to the GitLab project, to create pipeline schedules.
- For AWS sources: permission to create an IAM OIDC identity provider and an IAM role in each AWS
  account you collect from.
- A `vault:` and a `manual.pdf` source that point at buckets, not local paths. A CI job's local
  folder disappears when the job ends. Keys: [configuration reference](../configuration.md) and
  [Upload manual evidence](manual-evidence.md#1-configure-the-manual-evidence-source).

## 1. Scaffold the pipeline

From the repository root:

```bash
sigcomply init-ci --ci gitlab
```

This writes `.gitlab-ci.yml` with a hidden base job, `.sigcomply_base`, and six jobs that extend
it:

| Job | Runs when | Command |
|---|---|---|
| `compliance:on_push` | Every merge request, and pushes to the default branch | `sigcomply check --on-push` |
| `compliance:daily` | A scheduled pipeline with `CADENCE=daily` | `sigcomply check --cadence daily`, then `sigcomply evidence due --within-days 30` |
| `compliance:weekly` | A scheduled pipeline with `CADENCE=weekly` | `sigcomply check --cadence weekly` |
| `compliance:monthly` | A scheduled pipeline with `CADENCE=monthly` | `sigcomply check --cadence monthly` |
| `compliance:quarterly` | A scheduled pipeline with `CADENCE=quarterly` | `sigcomply check --cadence quarterly` |
| `compliance:annual` | A scheduled pipeline with `CADENCE=annual` | `sigcomply check --cadence annual` |

The base job installs the CLI release named in `SIGCOMPLY_VERSION` and mints an ID token with
the audience `https://api.sigcomply.com`. It writes that token to a file and exports
`AWS_WEB_IDENTITY_TOKEN_FILE`, so the AWS SDK inside the CLI assumes the role in `AWS_ROLE_ARN`.
The CLI reads the same token from `SIGCOMPLY_ID_TOKEN` for cloud submission.

`init-ci` refuses to overwrite an existing file; pass `--force` to replace it. It accepts only
`--framework soc2` and exits `3` for other values, including a config that sets
`framework: iso27001` when you pass no flag. The scaffolded jobs don't name a framework: `check`
reads `framework:` from `.sigcomply.yaml`. For ISO 27001, keep `framework: iso27001` and run
`sigcomply init-ci --ci gitlab --framework soc2`; the daily job keeps its `evidence due` step.
[`examples/gitlab-ci.yml`](../../examples/gitlab-ci.yml) is a fallback without that step.

## 2. Set the variables

Edit the `variables:` block at the top of `.gitlab-ci.yml`, or set the same names as project
CI/CD variables:

| Variable | Set to |
|---|---|
| `SIGCOMPLY_VERSION` | A release tag. A release build of the CLI writes its own version here; a build from source writes `latest`. Bump it when you upgrade. |
| `AWS_REGION` | The region of your AWS sources. |
| `AWS_ROLE_ARN` | The role you create in step 3. |

If you collect nothing from AWS, leave `AWS_ROLE_ARN` unset (delete the line) so the AWS SDK does
not try to assume the placeholder role.

## 3. Create the AWS OIDC provider and role

The pipeline uses one ID token, with the audience `https://api.sigcomply.com`, for AWS and for
SigComply Cloud. AWS accepts it only if the IAM OIDC provider lists that audience as a client ID. For self-managed GitLab, replace `gitlab.com` with your instance's host.

1. Create the provider. If the account already has a provider for `https://gitlab.com`, add the
   client ID to it instead (`aws iam add-client-id-to-open-id-connect-provider`).

   ```bash
   aws iam create-open-id-connect-provider \
     --url https://gitlab.com \
     --client-id-list https://api.sigcomply.com
   ```

2. Create a role with this trust policy. Replace the account ID and `my-group/my-project`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::111122223333:oidc-provider/gitlab.com"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "gitlab.com:aud": "https://api.sigcomply.com"
           },
           "StringLike": {
             "gitlab.com:sub": "project_path:my-group/my-project:*"
           }
         }
       }
     ]
   }
   ```

3. Attach read-only permissions: the AWS managed `ReadOnlyAccess` policy, or the per-source
   permissions in the [sources reference](../reference/sources.md#aws). If the vault is in S3,
   also allow `s3:PutObject` on the vault bucket. `ReadOnlyAccess` already covers listing and
   reading the manual-evidence bucket.

4. Put the role's ARN in `AWS_ROLE_ARN`.

## 4. Create one pipeline schedule per cadence

Cadence jobs run only in scheduled pipelines. In your project:

1. Go to **Build > Pipeline schedules > New schedule**.
2. Enter the interval for the cadence. These match the GitHub templates:

   | `CADENCE` | Interval pattern |
   |---|---|
   | `daily` | `0 2 * * *` |
   | `weekly` | `0 2 * * 1` |
   | `monthly` | `0 2 20 * *` |
   | `quarterly` | `0 2 20 3,6,9,12 *` |
   | `annual` | `0 2 20 12 *` |

3. Under **Variables**, add `CADENCE` with the value from the first column.
4. Save. Repeat for each cadence.

The longer cadences run on day 20, inside the period, because the CLI takes the audit period
from the commit time of `HEAD`. A run on day 1 can land in a period that just opened, whose
manual-evidence folders cannot hold anything yet.

## 5. Optional: send results to SigComply Cloud

To send pass/fail counts to the paid dashboard, add this to `.sigcomply.yaml`:

```yaml
cloud:
  base_url: https://sigcomply.com
```

Without `cloud.base_url`, the CLI sends nothing. Connect the repository in the dashboard first:
[Connect to SigComply Cloud](cloud-dashboard.md).

## 6. Commit and run

```bash
git add .gitlab-ci.yml .sigcomply.yaml
git commit -m "ci: add SigComply compliance pipeline"
git push
```

## Verify

1. The push runs `compliance:on_push` on the default branch. Open it under **Build > Pipelines**.
2. On **Build > Pipeline schedules**, start the daily schedule with **Run pipeline schedule**.
3. In the `compliance:daily` job log, check that collection started for each source and the run
   summary lists your policies. The job fails with exit code `1` when a policy fails, `2` on an
   execution error and `3` on a configuration error ([exit codes](../reference/commands.md)).
   Set `ci.fail_on_violation: false` to keep the job green when policies fail.
4. If you set `cloud.base_url`, the log shows `submission accepted (HTTP 201)` or a `submit:`
   warning ([Troubleshooting](troubleshooting.md#cloud-submission)).

## Next steps

- [Connect to SigComply Cloud](cloud-dashboard.md).
- [Upload manual evidence](manual-evidence.md).
- [Verify evidence](verify-evidence.md).
