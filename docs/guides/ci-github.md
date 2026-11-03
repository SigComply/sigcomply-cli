# Run SigComply in GitHub Actions

Add SigComply's scheduled and on-push workflows to a GitHub repository. The workflows get AWS
credentials through GitHub OIDC, so you store no AWS keys.

## Prerequisites

- A repository on GitHub with a working `.sigcomply.yaml` ([Add an evidence source](configure-sources.md)).
- The CLI installed on your machine ([install guide](install.md)).
- For AWS sources: permission to create an IAM OIDC identity provider and IAM roles in each AWS
  account you collect from.
- A `vault:` and a `manual.pdf` source that point at buckets, not local paths. A CI job's local
  folder disappears when the job ends. Keys: [configuration reference](../configuration.md) and
  [Upload manual evidence](manual-evidence.md#1-configure-the-manual-evidence-source).
- A repository or organization secret for each GitHub, GitLab, Okta or Active Directory source:
  [Supply credentials in CI](configure-sources.md#supply-github-gitlab-okta-and-active-directory-credentials-in-ci).

## 1. Scaffold the workflows

From the repository root:

```bash
sigcomply init-ci --ci github
```

If the files already exist, `init-ci` stops with exit `3`; pass `--force` to replace them. It
writes two files to `.github/workflows/`:

| File | Runs | Command |
|---|---|---|
| `compliance-scheduled.yml` | 02:00 UTC daily, and **Run workflow** | `sigcomply check --scheduled`, then `sigcomply evidence due --within-days 30` |
| `compliance-on-push.yml` | Pushes to `main` and pull requests, except from forks (a fork's pull request gets no OIDC token) | `sigcomply check --pr` |

The scheduled run evaluates the policies that are due or failed last time and carries the rest
forward. Only this run updates the state in the vault and sends results to the dashboard.

The `--pr` run evaluates the policies marked `on_push`: every automated policy in the shipped
frameworks. The `evidence due` step lists empty manual-evidence folders whose period ends within
30 days, and never fails the job.

For ISO 27001, see [Use another framework](#use-another-framework).

## 2. Pin the CLI version

Each workflow sets `SIGCOMPLY_VERSION` in its `env:` block. Set it to a release tag (v0.91.0 or
later) so every run installs the same CLI. The install step fails the job if the checksum or build
provenance doesn't match. Self-hosted runners need `gh` and `git`
([Install](install.md#prerequisites)).

## 3. Create the AWS OIDC provider and roles

Skip this step if you collect nothing from AWS, and delete the
`aws-actions/configure-aws-credentials` step from each workflow. Otherwise that step fails on the
placeholder role ARN.

The AWS step and the CLI each request their own GitHub OIDC token. The AWS step's token has the
audience `sts.amazonaws.com`. The CLI's token has the audience `https://api.sigcomply.com` and goes
only to SigComply. Never let an AWS role trust `https://api.sigcomply.com`: SigComply receives
every token with that audience, so such a role would trust tokens that leave your CI.

Each workflow assumes its own role:

| Role | Used by | Trusts | Writes to the vault |
|---|---|---|---|
| Scheduled role | `compliance-scheduled.yml` | the `main` branch only | run folders and the cadence state in `state/` |
| On-push role | `compliance-on-push.yml` | pull requests and `main` | run folders only, never `state/` |

A pull request runs the branch's workflow file, so anyone who can push a branch controls what the
on-push role does. That role can't write `state/`, so a branch can't change what the next
scheduled run carries forward.

1. Create the provider. If the account already has a provider for
   `token.actions.githubusercontent.com` with the client ID `sts.amazonaws.com`, reuse it.

   ```bash
   aws iam create-open-id-connect-provider \
     --url https://token.actions.githubusercontent.com \
     --client-id-list sts.amazonaws.com
   ```

2. Create the scheduled role with this trust policy. Replace the account ID, `my-org` and
   `my-repo`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "SigComplyScheduled",
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
             "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
           }
         }
       }
     ]
   }
   ```

   Protect `main` with a branch rule, so only reviewed changes run with this role.

3. Create the on-push role with this trust policy:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "SigComplyOnPush",
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
             "token.actions.githubusercontent.com:sub": [
               "repo:my-org/my-repo:pull_request",
               "repo:my-org/my-repo:ref:refs/heads/main"
             ]
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

5. Set `AWS_ROLE_ARN` in `compliance-scheduled.yml` to the scheduled role's ARN, and in
   `compliance-on-push.yml` to the on-push role's ARN. Set `AWS_REGION` in both to your region.

If a role you created earlier trusts `https://api.sigcomply.com`, fix it:
[Troubleshooting](troubleshooting.md#an-aws-role-trusts-httpsapisigcomplycom).

## 4. Optional: send results to the SigComply dashboard

Connect the repository in the dashboard and copy its **Project ID**:
[Connect to the SigComply dashboard](cloud-dashboard.md). Then add this to `.sigcomply.yaml`:

```yaml
cloud:
  base_url: https://sigcomply.com
  project_id: prj_7Xq2mKp9RtV4wNc8Bz3a   # the Project ID from your project's page
```

Without `cloud.base_url`, the CLI sends nothing. Without `cloud.project_id`, a scheduled run stops
with exit `3` before it collects anything. The workflows already grant `id-token: write`, which is
all the CLI needs to mint its token.

## 5. Commit and run

The scheduled run fails (exit `1`) until every document policy has a file for the current period.
To keep the job green while you upload them, set `ci.fail_on_violation: false` in
`.sigcomply.yaml` before you push.

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
   configuration error ([exit codes](../reference/commands.md#exit-codes)).
4. If you set `cloud.base_url`, the scheduled run's log shows `submission accepted (HTTP 201)` or
   a `submit:` warning ([Troubleshooting](troubleshooting.md#cloud-submission)).

## Use another framework

The workflows don't name a framework: `check` reads `framework:` from `.sigcomply.yaml`.
`init-ci` itself only knows `soc2`, and on an ISO 27001 config it exits `3`. Pass
`--framework soc2` so it writes the workflows anyway:

```sh
sigcomply init-ci --ci github --framework soc2
```

## Use a single workflow instead

To run one workflow instead of two, copy
[`examples/github-actions/basic.yml`](../../examples/github-actions/basic.yml) into
`.github/workflows/` and apply steps 3 to 5 above to it. It runs a full `sigcomply check` on
pushes to `main` and on its schedule with `AWS_ROLE_ARN` (the scheduled role), and `--pr` on pull
requests with `AWS_ON_PUSH_ROLE_ARN` (the on-push role). It skips pull requests from forks and has
no `evidence due` step.

## Next steps

- [Connect to the SigComply dashboard](cloud-dashboard.md).
- [Upload manual evidence](manual-evidence.md).
- [Verify evidence](verify-evidence.md).
