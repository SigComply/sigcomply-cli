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

This writes two files to `.github/workflows/`:

| File | Runs | Command |
|---|---|---|
| `compliance-scheduled.yml` | 02:00 UTC daily, and **Run workflow** | `sigcomply check --scheduled`, then `sigcomply evidence due --within-days 30` |
| `compliance-on-push.yml` | Pushes to `main` and pull requests | `sigcomply check --pr` |

`--scheduled` reads each policy's state from the vault, evaluates the policies whose cadence has
come due (or that failed last time), and carries the others forward. Every run therefore covers
every policy, and it is the only run that sends results to SigComply Cloud. A daily run evaluates
each policy at least once in every calendar window of its cadence, so a quarterly document is
read every quarter. The state lives in the vault, which is why the vault must be a bucket.

`--pr` evaluates the policies whose `on_push` attribute is true. In the shipped frameworks that
is every automated policy; document policies are excluded. A `--pr` run writes its results to
the vault but never submits to SigComply Cloud and never updates the cadence state, so a pull
request's branch and config can't become the project's recorded result.

The `evidence due` step lists empty manual-evidence folders whose period ends within 30 days. A
manual policy fails in every scheduled run until its folder for the current period has a file, so
upload during the period. The step runs with `continue-on-error: true`, so it never fails the job.

`init-ci` refuses to overwrite existing files; pass `--force` to replace them. It scaffolds SOC 2
only. For ISO 27001, see [Use another framework](#use-another-framework).

## 2. Check the pinned version

Each workflow sets `SIGCOMPLY_VERSION` in its `env:` block. A release build of the CLI writes its
own version there (for example `v0.88.4`); a build from source writes `latest`. Pin a release tag
so every run installs the same CLI, and bump it when you upgrade. The install step checks the
downloaded archive against the release's `checksums.txt` before extracting it.

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
2. Start the scheduled workflow (`compliance-scheduled.yml`) with **Run workflow**.
3. In the **Run SigComply** step log, check that collection started for each source and the run
   summary lists every policy of the framework. The first run evaluates all of them; later runs
   list the ones not yet due as `carried`. Document policies fail until you upload their files.
   The job fails with exit code `1` when a policy fails, `2` on an execution error and `3` on a
   configuration error ([exit codes](../reference/commands.md)). Set
   `ci.fail_on_violation: false` to keep the job green when policies fail.
4. If you set `cloud.base_url`, the log shows `submission accepted (HTTP 201)` or a `submit:`
   warning ([Troubleshooting](troubleshooting.md#cloud-submission)).

## Use another framework

`init-ci` accepts only `--framework soc2` and exits `3` for any other value, so it also exits `3`
when `.sigcomply.yaml` sets `framework: iso27001` and you pass no flag. The workflows it writes
don't name a framework: `check` reads `framework:` from `.sigcomply.yaml`. For ISO 27001, keep
`framework: iso27001` in the config and run:

```sh
sigcomply init-ci --ci github --framework soc2
```

The scaffolded set includes the `evidence due` step in the scheduled workflow. If you prefer a
single workflow, copy [`examples/github-actions/basic.yml`](../../examples/github-actions/basic.yml)
into `.github/workflows/` instead and apply steps 3 to 5 above to it. It runs a full
`sigcomply check` on pushes to `main` and on its schedule, `--pr` on pull requests, and has no
`evidence due` step.

## Next steps

- [Connect to SigComply Cloud](cloud-dashboard.md).
- [Upload manual evidence](manual-evidence.md).
- [Verify evidence](verify-evidence.md).
