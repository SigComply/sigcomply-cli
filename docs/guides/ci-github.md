# Run SigComply in GitHub Actions

Add scheduled SigComply workflows to a GitHub repository. The jobs use GitHub OIDC to assume a
read-only AWS role and, if you use the paid dashboard, to authenticate to SigComply Cloud. You
store no long-lived secret.

## Prerequisites

- A repository on GitHub with a working `.sigcomply.yaml` ([Add an evidence source](configure-sources.md)).
- The CLI installed on your machine ([install guide](install.md)).
- For AWS sources: permission to create an IAM OIDC identity provider and an IAM role in each AWS
  account you collect from.
- A `vault:` and a `manual.pdf` source that point at buckets, not local paths. A CI job's local
  folder disappears when the job ends. Keys: [configuration reference](../configuration.md) and
  [Upload manual evidence](manual-evidence.md#1-configure-the-manual-evidence-source).

## 1. Scaffold the workflows

From the repository root:

```bash
sigcomply init-ci --ci github
```

This writes six files to `.github/workflows/`:

| File | Runs | Command |
|---|---|---|
| `compliance-daily.yml` | 02:00 UTC daily | `sigcomply check --cadence daily`, then `sigcomply evidence due --within-days 30` |
| `compliance-weekly.yml` | 02:00 UTC Mondays | `sigcomply check --cadence weekly` |
| `compliance-monthly.yml` | 02:00 UTC on day 20 of each month | `sigcomply check --cadence monthly` |
| `compliance-quarterly.yml` | 02:00 UTC on 20 Mar, Jun, Sep, Dec | `sigcomply check --cadence quarterly` |
| `compliance-annual.yml` | 02:00 UTC on 20 Dec | `sigcomply check --cadence annual` |
| `compliance-on-push.yml` | Pushes to `main` and pull requests | `sigcomply check --on-push` |

The longer cadences run on day 20, inside the period, because the CLI takes the audit period
from the commit time of `HEAD`. A run on day 1 can land in a period that just opened, whose
manual-evidence folders cannot hold anything yet.

Every cadence workflow also has a `workflow_dispatch` trigger, so you can start it from the
**Actions** tab. The `evidence due` step lists empty manual-evidence folders and never fails the
job.

`init-ci` refuses to overwrite existing files; pass `--force` to replace them. It scaffolds SOC 2
only. For ISO 27001, see [Use another framework](#use-another-framework).

## 2. Check the pinned version

Each workflow sets `SIGCOMPLY_VERSION` in its `env:` block. A release build of the CLI writes its
own version there (for example `v0.88.4`); a build from source writes `latest`. Pin a release tag
so every run installs the same CLI, and bump it when you upgrade.

## 3. Create the AWS OIDC provider and role

Skip this step if you collect nothing from AWS, and delete the
`aws-actions/configure-aws-credentials` step from each workflow. Otherwise that step fails on the
placeholder role ARN.

The workflows request a GitHub OIDC token with the audience `https://api.sigcomply.com` and pass
it to `aws-actions/configure-aws-credentials`. The templates use this one audience for AWS and for
SigComply Cloud, whether or not you use the dashboard. AWS accepts the token only if the IAM OIDC
provider lists that audience as a client ID.

1. Create the provider with the SigComply audience. If the account already has a provider for
   `token.actions.githubusercontent.com`, add the client ID to it instead
   (`aws iam add-client-id-to-open-id-connect-provider`).

   ```bash
   aws iam create-open-id-connect-provider \
     --url https://token.actions.githubusercontent.com \
     --client-id-list https://api.sigcomply.com
   ```

2. Create a role with this trust policy. Replace the account ID, `my-org` and `my-repo`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "token.actions.githubusercontent.com:aud": "https://api.sigcomply.com"
           },
           "StringLike": {
             "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:*"
           }
         }
       }
     ]
   }
   ```

3. Attach read-only permissions to the role: the AWS managed `ReadOnlyAccess` policy, or the
   per-source permissions in the [sources reference](../reference/sources.md#aws). If the vault is
   in S3, also allow `s3:PutObject` on the vault bucket. `ReadOnlyAccess` already covers listing
   and reading the manual-evidence bucket.

4. In each workflow's `env:` block, set `AWS_ROLE_ARN` to the role's ARN and `AWS_REGION` to your
   region.

## 4. Optional: send results to SigComply Cloud

To send pass/fail counts to the paid dashboard, add this to `.sigcomply.yaml`:

```yaml
cloud:
  base_url: https://sigcomply.com
```

Without `cloud.base_url`, the CLI sends nothing. The workflows already grant
`id-token: write`, which is all the CLI needs to mint its token. Connect the repository in the
dashboard first: [Connect to SigComply Cloud](cloud-dashboard.md).

## 5. Commit and run

```bash
git add .github/workflows/ .sigcomply.yaml
git commit -m "ci: add SigComply compliance workflows"
git push
```

## Verify

1. The push starts the on-push workflow (`compliance-on-push.yml`). Open it in the **Actions**
   tab.
2. Start the daily workflow (`compliance-daily.yml`) with **Run workflow**.
3. In the **Run SigComply** step log, check that collection started for each source and the run
   summary lists your policies. The job fails with exit code `1` when a policy fails, `2` on an
   execution error and `3` on a configuration error ([exit codes](../reference/commands.md)).
   Set `ci.fail_on_violation: false` to keep the job green when policies fail.
4. If you set `cloud.base_url`, the log shows `submission accepted (HTTP 201)` or a `submit:`
   warning ([Troubleshooting](troubleshooting.md#cloud-submission)).

## Use another framework

`init-ci` scaffolds SOC 2 only and exits `3` for any other framework. For ISO 27001, copy
[`examples/github-actions/basic.yml`](../../examples/github-actions/basic.yml) into
`.github/workflows/`. The CLI reads the framework from `framework:` in `.sigcomply.yaml`, so the
workflow needs no framework flag. Apply steps 3 to 5 above to the copied file.

## Next steps

- [Connect to SigComply Cloud](cloud-dashboard.md).
- [Upload manual evidence](manual-evidence.md).
- [Verify evidence](verify-evidence.md).
