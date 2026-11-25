# Live E2E tier

The live E2E tier runs a released `sigcomply` binary against permanent fixture accounts in AWS,
GCP, Azure, GitHub, GitLab, Okta and Entra ID. It writes the vault to the provider's real storage
(S3, GCS, Azure Blob; a local folder for SaaS), reads the run back and verifies it. It is the only
place real-API correctness for the cloud sources is checked. The E2E repos run four read-only
sources each and check only that no policy has the status `error`
([11-testing-strategy.md](../architecture/11-testing-strategy.md) §2, L4b).

Read this before you change `cmd/sigcomply/live_e2e*_test.go`, `.github/workflows/live-e2e*.yml`
or the live gate in `release-promote.yml`, or when a live run fails.

## What runs, and when

| Trigger | Workflow | Binary | On failure |
|---|---|---|---|
| Each release candidate, when the repository variable `LIVE_E2E` is `on` | `release-promote.yml` job `live-e2e`, which calls `live-e2e.yml` with the tag | the prerelease's published asset | the release stays a prerelease (same as the E2E gate) |
| By hand | `live-e2e.yml` `workflow_dispatch`, optional `tag` | that tag, or the latest release | red run |
| Nightly, 03:00 UTC, only when `LIVE_E2E` and `LIVE_E2E_NIGHTLY` are both `on` (off by default) | `live-e2e-nightly.yml`, which calls `live-e2e.yml` | the latest release | red run, and the `live-drift` issue is opened or commented |

Each run costs cents (vault writes and a few billed list calls), so by default the tier runs only
on release candidates and manual dispatch. Set `LIVE_E2E_NIGHTLY` to `on` to also run it every night as a drift alarm.

`live-e2e.yml` resolves the tag, checks out that tag (so the harness matches the binary), installs
the asset with `scripts/install.sh` and `SIGCOMPLY_REQUIRE_PROVENANCE=1`, and runs one job per
provider:

| Job | Test | Credentials | Vault |
|---|---|---|---|
| `aws` | `TestLiveE2E_AWS` | OIDC, `aws-actions/configure-aws-credentials` (audience `sts.amazonaws.com`) | S3 |
| `gcp` | `TestLiveE2E_GCP` | OIDC, `google-github-actions/auth` (workload identity federation) | GCS |
| `azure` | `TestLiveE2E_Azure` | OIDC, `azure/login` (federated credential, no secret) | Azure Blob |
| `saas` | `TestLiveE2E_SaaS`, then every per-source `Test*Live*` under `internal/` | environment secrets | local folder |

The `aws` and `gcp` jobs always run. The `azure` and `saas` jobs run unless the repository
variable `LIVE_E2E_AZURE` or `LIVE_E2E_SAAS` is `off`. Use that while a provider's test accounts
do not exist yet. A skipped job does not fail the tier, so the release is still promoted, and
promote warns that it was not live-tested on that provider.

Each test, for SOC 2 and then ISO 27001:

1. Writes a `.sigcomply.yaml` with the provider's sources, a local `manual.pdf` source pointing at
   an empty folder (`check` refuses to plan without one; manual policies then fail, which is
   exit 1), and the vault under a prefix unique to the run (`live-e2e/<UTC time>-<random>`).
2. Runs `sigcomply check --no-cloud`. Asserts exit 0 or 1 and `error=0` on the counts line.
3. Lists the run folder in the vault, runs `sigcomply report --view integrity` against it
   (manifest signature and every file hash) and verifies every envelope's signature with
   `sign.VerifyEnvelope`.

After both frameworks, it fails when a configured source is reported `unbound-source` by both: a
source no policy reads is a renamed source or a lost evidence type.

`LIVE_E2E_REQUIRED=1` (set by the workflow) turns a missing variable into a failure instead of a
skip, and refuses to build the binary from source when `SIGCOMPLY_E2E_BINARY` is unset. Without
it, each test skips unless its variables are set, so `make test-live` and `go test -tags live
./...` stay safe with no credentials.

The harness is in `cmd/sigcomply/live_e2e_harness_test.go`, untagged, and
`live_e2e_harness_self_test.go` runs it on every push against the GitHub cassette server and a
local vault. The provider tests and source allowlists are in `cmd/sigcomply/live_e2e_test.go`
(`//go:build live`). `test.yml` runs `go vet -tags live ./...` so a refactor cannot break them
unseen.

## Output rules

The repository and its Actions logs are public. The CLI's output names cloud resources (ARNs,
account, project and subscription IDs, e-mails).

- Never print the child's stdout or stderr. The harness writes them to files in the test's temp
  directory.
- Build failure messages only from parsed values: policy IDs, statuses, source IDs, exit codes,
  paths inside the run folder and the counts line. Never a `result.json` reason or an error's
  text.
- In a per-source live test, report an error with `sourcetest.PublicError(err)` and schema drift
  as counts per evidence type, never with record IDs.
- Never run `go test` with `-v`, upload an artifact, or `cat` a report in these workflows.

## Variables and secrets

All of these live in the `live-e2e` GitHub environment, except the switches (`LIVE_E2E`,
`LIVE_E2E_NIGHTLY`, `LIVE_E2E_AZURE`, `LIVE_E2E_SAAS`), which are repository variables. Every account identifier is a secret, not a variable: GitHub prints a step's inputs in
the public log and masks only secrets (`TestLiveE2E_IdentifiersAreSecrets` pins this). Optional
ones add env-gated sources.

| Name | Kind | Holds |
|---|---|---|
| `LIVE_E2E` | repository variable | `on` to gate every release on this tier |
| `LIVE_E2E_NIGHTLY` | repository variable, optional | `on` (with `LIVE_E2E` on) to also run the tier every night; unset is off |
| `LIVE_E2E_AZURE` | repository variable, optional | `off` to skip the `azure` job; unset runs it |
| `LIVE_E2E_SAAS` | repository variable, optional | `off` to skip the `saas` job; unset runs it |
| `LIVE_E2E_AWS_ROLE_ARN` | secret | ARN of the read-only role the `aws` job assumes |
| `LIVE_E2E_AWS_REGION` | variable | Region of the fixture sources and the vault bucket |
| `LIVE_E2E_AWS_VAULT_BUCKET` | secret | S3 bucket for the vault |
| `LIVE_E2E_AWS_IDENTITY_STORE_ID` | secret, optional | Identity Center identity store ID; adds `aws.identity_center` |
| `LIVE_E2E_AWS_INSPECTOR` | variable, optional | `on` once Inspector is activated; adds `aws.inspector` |
| `LIVE_E2E_GCP_WIF_PROVIDER` | secret | Full resource name of the workload identity provider |
| `LIVE_E2E_GCP_SERVICE_ACCOUNT` | secret | E-mail of the service account the job impersonates |
| `LIVE_E2E_GCP_PROJECT_ID` | secret | Fixture project ID |
| `LIVE_E2E_GCP_VAULT_BUCKET` | secret | GCS bucket for the vault |
| `LIVE_E2E_GCP_ORGANIZATION_ID` | secret, optional | Organization ID; adds `gcp.scc` |
| `LIVE_E2E_GCP_WORKSPACE_SERVICE_ACCOUNT` | secret, optional | With the next one, adds `gcp.directory` and `gcp.cloud_identity` |
| `LIVE_E2E_GCP_WORKSPACE_ADMIN` | secret, optional | Workspace super admin the service account acts as (domain-wide delegation) |
| `LIVE_E2E_AZURE_CLIENT_ID` | secret | App registration with the federated credential |
| `LIVE_E2E_AZURE_TENANT_ID` | secret | Its tenant |
| `LIVE_E2E_AZURE_SUBSCRIPTION_ID` | secret | Fixture subscription |
| `LIVE_E2E_AZURE_STORAGE_ACCOUNT` | secret | Storage account name for the vault |
| `LIVE_E2E_AZURE_VAULT_CONTAINER` | secret | Blob container for the vault |
| `GH_TEST_TOKEN`, `GH_TEST_ORG` | secrets | GitHub token and org (mapped to `GITHUB_TEST_*`; a secret name cannot start with `GITHUB_`) |
| `GITLAB_TEST_TOKEN`, `GITLAB_TEST_GROUP`, `GITLAB_TEST_BASE_URL` (optional) | secrets | GitLab token, group, self-managed URL |
| `OKTA_TEST_TOKEN`, `OKTA_TEST_ORG_URL` | secrets | Okta API token and org URL |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | secrets | Entra app registration for Microsoft Graph |

The SaaS credentials and their permissions are the ones in
[11-testing-strategy.md](../architecture/11-testing-strategy.md) §7. Keep them as environment
secrets only, and delete any repository-level copy: a repository secret reaches every workflow.

## Sources and what the fixture accounts need

Every source in the allowlist must run with zero errors in a mostly empty account. An empty
account gives zero records for most sources, and that is a pass for this tier. A source whose API
is disabled returns an error, which fails the run, so enable each API listed.

| Provider | Allowlist (committed) | The account needs | Env-gated extras |
|---|---|---|---|
| AWS | `aws.acm`, `aws.backup`, `aws.cloudtrail`, `aws.cloudwatch`, `aws.config`, `aws.dynamodb`, `aws.ec2`, `aws.ecr`, `aws.eks`, `aws.guardduty`, `aws.iam`, `aws.iam_access_key`, `aws.kms`, `aws.lambda`, `aws.password_policy`, `aws.rds`, `aws.s3`, `aws.secretsmanager`, `aws.security_alert`, `aws.security_group`, `aws.security_services`, `aws.vpc` | Nothing enabled. No trail, Config recorder or GuardDuty detector reads as zero records; Macie, Inspector and Security Hub not enabled read as "disabled" records | `aws.identity_center`: an Identity Center instance in the region (free). `aws.inspector`: Inspector activated (free trial, then paid per scanned resource) |
| GCP | `gcp.artifactregistry`, `gcp.asset`, `gcp.audit`, `gcp.backup`, `gcp.certs`, `gcp.compute`, `gcp.firestore`, `gcp.firewall`, `gcp.gke`, `gcp.iam`, `gcp.kms`, `gcp.logging`, `gcp.network`, `gcp.secretmanager`, `gcp.sql`, `gcp.storage` | These APIs enabled: `artifactregistry`, `backupdr`, `certificatemanager`, `cloudasset`, `cloudkms`, `cloudresourcemanager`, `compute`, `container`, `firestore`, `logging`, `secretmanager`, `sqladmin`, `storage` (all `*.googleapis.com`). Enabling and listing cost nothing; confirm `backupdr` before relying on it | `gcp.scc`: an organization and org-level Security Command Center viewer roles. `gcp.directory`, `gcp.cloud_identity`: a Workspace tenant with domain-wide delegation |
| Azure | `azure.acr`, `azure.aks`, `azure.backup`, `azure.certs`, `azure.compute`, `azure.cosmos`, `azure.defender`, `azure.keyvault`, `azure.monitor`, `azure.network`, `azure.policy`, `azure.sql`, `azure.storage` | These resource providers registered (free): `Microsoft.ContainerRegistry`, `Microsoft.ContainerService`, `Microsoft.Insights`, `Microsoft.RecoveryServices`, `Microsoft.Web`, `Microsoft.CertificateRegistration`, `Microsoft.Compute`, `Microsoft.Network`, `Microsoft.DocumentDB`, `Microsoft.Security`, `Microsoft.ResourceGraph`, `Microsoft.KeyVault`, `Microsoft.OperationalInsights`, `Microsoft.Sql`, `Microsoft.DBforPostgreSQL`, `Microsoft.DBforMySQL`, `Microsoft.Storage`. Leave Defender plans on Free | none |
| SaaS | `github`, `gitlab`, `okta`, `azure.entra` | The free accounts in [11-testing-strategy.md](../architecture/11-testing-strategy.md) §7 | none |

Active Directory is out of scope: its live test needs a local Samba container. The Active
Directory and Cloud Identity per-source live tests still log raw errors, record IDs and (Cloud
Identity, on purpose) raw bodies, and run only on a developer machine. Never add their variables
to the `live-e2e` environment: the `saas` job runs every `Test*Live*` under `internal/`.

Never create expensive resources (clusters, databases, VMs) in the fixture accounts to make a
policy pass. Their non-empty mapping is covered by cassettes. A resource you do keep is named with
the `sigcomply-e2e-` prefix.

## One-time setup

Do this once per account. Pin every trust to the subject
`repo:SigComply/sigcomply-cli:environment:live-e2e`, which only a job in the `live-e2e`
environment of this repository can present.

The AWS account and GCP project can be the ones the E2E repos use (GitHub: AWS; GitLab: GCP).
Give the tier its own role, pool, service account and bucket in them.

1. GitHub: create the environment `live-e2e`. Under deployment branches and tags, allow the branch
   `main` and tags matching `v*` (the re-release path dispatches `release.yml` from a tag). Add the
   variables and secrets above.
2. AWS:
   1. Add the IAM OIDC provider `token.actions.githubusercontent.com`, audience
      `sts.amazonaws.com`, unless the account has it already. Then reuse it: an account holds
      one provider per URL.
   2. Create a role that trusts it with `StringEquals` on `token.actions.githubusercontent.com:aud`
      = `sts.amazonaws.com` and `token.actions.githubusercontent.com:sub` = the subject above.
      Never the SigComply Cloud audience (AGENTS.md invariant 6).
   3. Attach the `SecurityAudit` managed policy, and an inline policy allowing `s3:PutObject`,
      `s3:GetObject` and `s3:ListBucket` on the vault bucket only.
   4. Create the vault bucket with public access blocked and a lifecycle rule that expires
      objects under `live-e2e/` after 14 days.
   5. Add two budgets with e-mail alerts, unless the account has them: `sigcomply-test-monthly`
      ($10 a month) and `sigcomply-ci-runaway` ($25 a month), whose action attaches the
      deny-all policy `sigcomply-ci-deny-all` to every CI role, this one included.
3. GCP:
   1. Create a workload identity pool and an OIDC provider for
      `https://token.actions.githubusercontent.com`, mapping `google.subject` to `assertion.sub`,
      with the attribute condition `assertion.sub == 'repo:SigComply/sigcomply-cli:environment:live-e2e'`.
   2. Create a service account. Grant the pool's principal for that subject
      `roles/iam.workloadIdentityUser` on it.
   3. Grant the service account `roles/viewer`, `roles/iam.securityReviewer` and
      `roles/cloudasset.viewer` (for `gcp.asset`) on the project, and `roles/storage.objectUser`
      on the vault bucket only.
   4. Enable the APIs in the table, plus `iam`, `iamcredentials` and `sts`, which workload
      identity federation needs. Create the vault bucket with uniform access and a lifecycle
      rule that deletes objects older than 14 days.
   5. Add a $5 a month budget with e-mail alerts on the project, unless it has one.
4. Azure:
   1. Create an app registration with a federated credential: issuer
      `https://token.actions.githubusercontent.com`, subject as above, audience
      `api://AzureADTokenExchange`. No client secret.
   2. Grant it `Reader` on the subscription and `Storage Blob Data Contributor` on the vault
      container only.
   3. Register the resource providers in the table. Create the storage account and container,
      with a lifecycle management rule that deletes blobs under `live-e2e/` after 14 days.
5. Wait until a release that contains the tier is the latest release: with `LIVE_E2E` off,
   releases are promoted without it. The workflow checks out the tag it tests, so an older tag
   has no live tests to run.
6. Dispatch `live-e2e.yml` from `main` (any other branch fails at once) with no tag, so it tests
   the latest release, and read every job's result. When every job passes, set the repository
   variable `LIVE_E2E` to `on`. That turns on the release gate. If a provider's accounts are not
   set up yet, set `LIVE_E2E_AZURE` or `LIVE_E2E_SAAS` to `off` first, and remove it once that
   provider's job passes. To also run the tier nightly, set `LIVE_E2E_NIGHTLY` to `on`.

## When a run fails

The log says which test, framework and check failed, by policy ID, source ID or vault path. It
never says why a policy errored (that text names resources). To see the CLI's own output,
reproduce locally with `LIVE_E2E_OUTPUT_DIR` set.

1. Release run: if the cause was outside the release (vendor outage, expired credential), fix it
   and use "Re-run failed jobs" on the release run. If the release is wrong, fix forward; it stays
   a prerelease. Never promote by hand without a passing live run for that tag.
2. Nightly run (only when `LIVE_E2E_NIGHTLY` is `on`): work the `live-drift` issue. A vendor change gets the remediation in
   [11-testing-strategy.md](../architecture/11-testing-strategy.md) §7.
3. To switch the tier off while a vendor is down, set `LIVE_E2E` to anything but `on`. That
   skips both the release gate and the nightly run; promote then warns that the release was not
   live-tested. To switch off only Azure or SaaS, set `LIVE_E2E_AZURE` or `LIVE_E2E_SAAS` to
   `off`; promote then warns that the release was not live-tested on that provider.
4. Every call of the `aws` job fails with AccessDenied: the AWS budget `sigcomply-ci-runaway` may
   have attached the deny-all policy `sigcomply-ci-deny-all` to the CI roles. Find why the spend
   rose, then detach the policy: reverse the action in the Budgets action history, or run
   `aws iam detach-role-policy` on each role.

Local reproduction, with only the fixture account's credentials visible (AGENTS.md rule 13).
Create the throwaway home, log in to the fixture account inside it, then run the test. The Go
SDKs ignore `CLOUDSDK_CONFIG`, so name the credentials file with `GOOGLE_APPLICATION_CREDENTIALS`:

```sh
S="$(mktemp -d)"
CLOUDSDK_CONFIG="$S/gcloud" gcloud auth application-default login
env -i HOME="$S" PATH="$PATH" \
  GOPATH="$(go env GOPATH)" GOCACHE="$(go env GOCACHE)" GOMODCACHE="$(go env GOMODCACHE)" \
  AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
  CLOUDSDK_CONFIG="$S/gcloud" AZURE_CONFIG_DIR="$S/azure" \
  GOOGLE_APPLICATION_CREDENTIALS="$S/gcloud/application_default_credentials.json" \
  LIVE_E2E_GCP_PROJECT_ID=... LIVE_E2E_GCP_VAULT_BUCKET=... \
  go test -tags live -count=1 -run '^TestLiveE2E_GCP$' ./cmd/sigcomply
```

Without `SIGCOMPLY_E2E_BINARY` the test builds the binary from your checkout. Add
`LIVE_E2E_OUTPUT_DIR=<folder>` to keep each run's configs and the CLI's stdout and stderr
(`check-<framework>.stdout` and so on) under that folder; otherwise they are deleted with the
test's temp directory. Delete the folder when done: it holds account identifiers.
