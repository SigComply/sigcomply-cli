# Source reference

Each entry under `sources:` in `.sigcomply.yaml` is keyed by a source ID from this page. This page
lists, per source, the keys it reads, how it finds credentials, the read access it needs, the
evidence types it emits, and its known limits. File grammar, instances and storage keys are in
the [configuration reference](../configuration.md). Setup steps are in
[Configure sources](../guides/configure-sources.md).

Every source only reads. Each one resolves its credentials before collection starts; a listed
source with no usable credentials stops the run with exit code `3`. A policy accepts evidence
types, not sources, so any source that emits a type a policy accepts can satisfy it.

## Source caveats

These fields are emitted with a default value (almost always `false`) because the source cannot
read them. The default can fail a policy but never pass one. When a policy reads one, the plan
prints a `source-caveat:` warning naming the policies and, where another bound source can answer,
the `bindings:` entry that pins the slot to it. Caveats never change a status, a count, or the
score.

An absolute caveat means no API exposes the value; record an exception or upload manual evidence.
A conditional caveat means a more privileged token or a higher product tier can read it.

| Source | Field | Kind | Why |
|---|---|---|---|
| `aws.identity_center` | `directory_user.mfa_enabled` | Absolute | AWS publishes no per-user MFA API for Identity Center. |
| `github` | `source_control_org_policy.two_factor_required` | Conditional | GitHub returns the org 2FA requirement only to a token with `admin:org`. |
| `gitlab` | `directory_user.mfa_enabled` | Absolute on gitlab.com | GitLab returns a member's 2FA state only to an instance administrator. A group-owner token does not see it, so on gitlab.com the field is always `false`. On self-managed GitLab an instance-admin token reads it. |
| `gitlab` | `git_repository.secret_scanning_enabled` | Absolute | Secret Detection is configured in `.gitlab-ci.yml`; no settings API exposes it. |
| `gitlab` | `git_repository.code_scanning_enabled` | Absolute | Same, for SAST. |
| `gitlab` | `git_repository.dependabot_alerts_enabled` | Absolute | Same, for Dependency Scanning. |
| `gitlab` | `git_repository.requires_signed_commits` | Conditional | A Premium push rule; on Free, or with no push rule, the read returns 404. |
| `gitlab` | `git_repository.require_code_owner_reviews` | Conditional | A Premium protection setting; on Free, or with no exact-name rule on the default branch, it reads `false`. |
| `gitlab` | `git_repository.required_reviewers_count` | Conditional | Approval rules are Premium; on Free the count reads `0`. |
| `azure.keyvault` | `secret.rotation_enabled` | Absolute | Key Vault has no API-readable secret rotation policy. |
| `azure.cosmos` | `nosql_table.deletion_protection` | Absolute | Cosmos DB has no deletion-protection property; Azure uses resource locks, which this source does not read. |
| `azure.sql` | `managed_database_instance.deletion_protection` | Absolute | Same, for Azure SQL and the PostgreSQL and MySQL flexible servers. |
| `azure.monitor` | `audit_log_trail.kms_encrypted` | Absolute | The Activity Log exposes no customer-managed-key state. |

## AWS

### Keys

Every `aws.*` source reads the same keys.

| Key | Required | Default | Effect |
|---|---|---|---|
| `region` | no | `vault.region`, then the SDK region (`AWS_REGION`) | Region to query. A regional source reads only this region; see [Regions](#regions). |
| `role_arn` | no | none | IAM role to assume from the ambient credentials. Use it to read a second account. A role that cannot be assumed stops the run. |
| `external_id` | no | none | External ID for the role's trust policy. |
| `role_session_name` | no | `sigcomply` | Session name shown in CloudTrail. |
| `identity_store_id` | no | discovered with `sso:ListInstances` | `aws.identity_center` only. Required when more than one Identity Center instance is visible. |

There is no `profile` key. In CI, `AWS_ACCESS_KEY_ID` takes precedence over a profile.

### Regions

`aws.iam`, `aws.iam_access_key` and `aws.password_policy` read account-wide data, and `aws.s3`
reads every bucket in the account whatever its region. Every other `aws.*` source is regional:
it reads only the one region its `region` key names. Resources in other regions are not
evaluated, and nothing in the run says so.

To cover more regions, add one instance of each regional source per region:

```yaml
sources:
  aws.ec2:
    region: us-east-1
  "aws.ec2[eu]":
    region: eu-west-1
  aws.guardduty:
    region: us-east-1
  "aws.guardduty[eu]":
    region: eu-west-1
```

Policies such as `soc2.cc7.2.threat_detection_all_regions` judge the regions you configure, not
every region AWS offers. Don't add per-region instances of the account-wide sources above: they
read the same data again.

### Credentials

The AWS SDK default chain: environment variables, shared config and profile, web identity
(OIDC in CI), then the instance or task role. With `role_arn`, the CLI calls `sts:AssumeRole` from
those credentials, so the ambient principal needs that permission on the target role.

### Sources

| Source ID | Emits | API actions |
|---|---|---|
| `aws.acm` | `tls_certificate` | `acm:ListCertificates`, `acm:DescribeCertificate` |
| `aws.backup` | `backup_plan` | `backup:ListBackupPlans`, `backup:GetBackupPlan` |
| `aws.cloudtrail` | `audit_log_trail` | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` |
| `aws.cloudwatch` | `log_group` | `logs:DescribeLogGroups` |
| `aws.config` | `config_change_tracking` | `config:DescribeConfigurationRecorders`, `config:DescribeConfigurationRecorderStatus` |
| `aws.dynamodb` | `nosql_table` | `dynamodb:ListTables`, `dynamodb:DescribeTable`, `dynamodb:DescribeContinuousBackups` |
| `aws.ec2` | `compute_instance` | `ec2:DescribeInstances`, `ec2:DescribeVolumes` |
| `aws.ecr` | `container_registry` | `ecr:DescribeRepositories`, `ecr:GetRepositoryPolicy` |
| `aws.eks` | `kubernetes_cluster` | `eks:ListClusters`, `eks:DescribeCluster` |
| `aws.guardduty` | `threat_detection_service` | `guardduty:ListDetectors`, `guardduty:GetDetector` |
| `aws.iam` | `directory_user.v2` | `iam:ListUsers`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:ListGroupsForUser`, `iam:ListAttachedGroupPolicies`, `iam:GenerateCredentialReport`, `iam:GetCredentialReport` |
| `aws.iam_access_key` | `iam_access_key` | `iam:ListUsers`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed` |
| `aws.identity_center` | `directory_user`, `roster_entry`, `iam_binding` | `sso:ListInstances`, `identitystore:ListUsers`; for `iam_binding` and `is_admin` also `identitystore:DescribeGroup`, `identitystore:ListGroupMemberships`, `sso:ListPermissionSets`, `sso:DescribePermissionSet`, `sso:ListManagedPoliciesInPermissionSet`, `sso:ListAccountsForProvisionedPermissionSet`, `sso:ListAccountAssignments` |
| `aws.inspector` | `vulnerability_finding` | `inspector2:ListFindings` |
| `aws.kms` | `kms_key` | `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus` |
| `aws.lambda` | `serverless_function` | `lambda:ListFunctions` |
| `aws.password_policy` | `password_policy.v2` | `iam:GetAccountPasswordPolicy` |
| `aws.rds` | `managed_database_instance` | `rds:DescribeDBInstances`, `rds:DescribeDBParameters`; for Aurora also `rds:DescribeDBClusters`, `rds:DescribeDBClusterParameters` |
| `aws.s3` | `object_storage_bucket` | `s3:ListAllMyBuckets`, `s3:GetEncryptionConfiguration`, `s3:GetBucketVersioning`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketLocation` |
| `aws.secretsmanager` | `secret` | `secretsmanager:ListSecrets` |
| `aws.security_alert` | `security_alert` | `cloudwatch:DescribeAlarms`, `logs:DescribeMetricFilters` |
| `aws.security_group` | `firewall_rule` | `ec2:DescribeSecurityGroups` |
| `aws.security_services` | `security_service` | `securityhub:DescribeHub`, `macie2:GetMacieSession`, `inspector2:BatchGetAccountStatus` |
| `aws.vpc` | `network` | `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs` |

Shipped policies that read user accounts accept both `directory_user` and `directory_user.v2`, so
`aws.iam` and the other identity sources fill the same slots.

There is no fixed list of which `aws.*` sources a framework needs. The plan's `coverage-gap` warning lists every slot with no configured source and the evidence types it accepts; add the sources above that emit them.

For `role_arn`, the target role's trust policy must allow the ambient principal to call `sts:AssumeRole`, with the `external_id` condition if you set one.

### Caveats

- `aws.iam` emits no email. To link IAM users to the [identity roster](../guides/identity-roster.md),
  add `experimental.roster.aliases` keyed by username, or list them in `non_human`. The root
  account is treated as non-human.
- `aws.iam` takes `unused_days` from the most recent console sign-in or access-key use in the
  credential report, which AWS refreshes at most every four hours. `has_console_access` is the
  report's `password_enabled`. `direct_policy_count` counts managed and inline policies attached
  to the user. `is_admin` is true only for the AWS-managed `AdministratorAccess` policy, attached
  to the user or to one of its groups; an inline or customer-managed policy that grants the same
  access is not detected.
- The MFA policies apply to every IAM user, including users that have only access keys. Record
  an exception for a programmatic-only user, or give it MFA.
- `aws.identity_center` must use the region of the Identity Center instance. Its users carry
  emails, so they join the roster directly. It can be the roster source. Used only as the roster,
  it needs just `sso:ListInstances` and `identitystore:ListUsers`.
- `aws.identity_center` cannot read per-user MFA. See [Source caveats](#source-caveats).
- `aws.acm` lists certificates of every key type. A certificate that was never issued (pending or
  failed validation) has no expiry date and emits no record. `auto_renew` is true only while ACM
  reports the certificate as eligible for renewal; an Amazon-issued certificate that no AWS
  resource uses is not renewed and reports `false`.
- `aws.ecr` reports `is_public: true` when the repository policy has an `Allow` statement for the
  principal `*` with no `Condition`. A statement with a condition counts as restricted.
- `aws.rds` reports an Aurora instance's deletion protection, Multi-AZ, backup, encryption and
  `ssl_required` from its DB cluster and cluster parameter group. `ssl_required` is omitted for
  engines without a TLS parameter (Oracle, SQL Server), and the SSL policy skips them.
- `aws.kms` reports `rotation_enabled: false` for customer-managed keys that KMS cannot rotate
  automatically (asymmetric, HMAC, imported key material, custom key store) without asking KMS.
  The shipped rotation policies check only enabled customer-managed keys, so keys that are disabled
  or pending deletion are left out; a key that cannot rotate still fails them. Record an
  exception for it.

## GCP

### Keys

| Source IDs | Key | Required | Effect |
|---|---|---|---|
| Project-scoped sources (table below) | `project_id` | yes | Project to read. Quote numeric values. |
| `gcp.scc` | `organization_id` | yes | Organization to read. |
| `gcp.directory` | `customer_id` | no | Workspace customer ID (`C0...`). Default `my_customer`, the credential's own customer. |
| `gcp.directory`, `gcp.cloud_identity` | `target_service_account` | no | Service account that ADC impersonates. ADC needs `roles/iam.serviceAccountTokenCreator` on it. |
| `gcp.directory`, `gcp.cloud_identity` | `impersonate_subject` | no | Workspace admin email for domain-wide delegation. Requires `target_service_account`. |

### Credentials

Application Default Credentials: `GOOGLE_APPLICATION_CREDENTIALS`, Workload Identity Federation
in CI (for example `google-github-actions/auth`), or `gcloud auth application-default login`
locally. All `gcp.*` sources share one identity per run.

### Sources

| Source ID | Scope | Emits | Role or access |
|---|---|---|---|
| `gcp.artifactregistry` | project | `container_registry` | `roles/artifactregistry.reader` |
| `gcp.asset` | project | `config_change_tracking` | `roles/cloudasset.viewer` |
| `gcp.audit` | project | `audit_log_trail` | `roles/iam.securityReviewer` and `roles/logging.viewer` |
| `gcp.backup` | project | `backup_plan` | `roles/backupdr.viewer` |
| `gcp.certs` | project | `tls_certificate` | `roles/certificatemanager.viewer` |
| `gcp.cloud_identity` | customer | `password_policy.v2` | Workspace super admin, normally through domain-wide delegation |
| `gcp.compute` | project | `compute_instance` | `roles/compute.viewer` |
| `gcp.directory` | customer | `directory_user`, `roster_entry` | Workspace admin role with Admin API privilege Users > Read, or domain-wide delegation |
| `gcp.firestore` | project | `nosql_table` | `roles/datastore.viewer` |
| `gcp.firewall` | project | `firewall_rule` | `roles/compute.viewer` |
| `gcp.gke` | project | `kubernetes_cluster` | `roles/container.viewer` |
| `gcp.iam` | project | `iam_binding` | `roles/iam.securityReviewer` |
| `gcp.kms` | project | `kms_key` | `roles/cloudkms.viewer` |
| `gcp.logging` | project | `log_group` | `roles/logging.viewer` |
| `gcp.network` | project | `network` | `roles/compute.viewer` |
| `gcp.scc` | organization | `threat_detection_service`, `security_service`, `vulnerability_finding` | Organization-level `roles/securitycenter.findingsViewer` and `roles/securitycenter.settingsViewer`, or `roles/securitycenter.adminViewer` |
| `gcp.secretmanager` | project | `secret` | `roles/secretmanager.viewer` |
| `gcp.sql` | project | `managed_database_instance` | `roles/cloudsql.viewer` |
| `gcp.storage` | project | `object_storage_bucket` | `roles/storage.viewer` |

### Caveats

- `gcp.directory` requests the scope `https://www.googleapis.com/auth/admin.directory.user.readonly`.
  Without a Workspace admin context the API returns 403 and the source fails. With a service
  account that is not in the domain, set `customer_id` explicitly.
- `gcp.cloud_identity` requests `https://www.googleapis.com/auth/cloud-identity.policies.readonly`.
  For domain-wide delegation, allow-list that exact scope string for the service account's client
  ID; a broader scope fails with `unauthorized_client`. If you delegate both Workspace sources,
  allow-list both scopes. The IAM Service Account Credentials API must be enabled in the target
  service account's project.
- `gcp.cloud_identity` is limited to 1 query per second per customer. Keep it on a daily or
  slower cadence.
- `gcp.scc` needs organization-level roles; a project-scoped CI service account usually lacks
  them.
- `gcp.certs` skips certificates that have never been issued (no expiry time yet). For a
  Google-managed certificate, `auto_renew` is `true` while Certificate Manager is managing it
  (state `ACTIVE` or `PROVISIONING`), `false` once provisioning has `FAILED`, and absent in any
  other state.
- When GCP reports that a zone or region was unreachable during a listing, `gcp.gke`, `gcp.sql`,
  `gcp.firestore`, `gcp.backup` and `gcp.certs` fail instead of evaluating the partial list.
  Policies bound to them get status `error` for that run.
- `gcp.audit` reports `is_enabled` and `is_multi_region` as `true` because Admin Activity audit
  logs are always on and project-wide in GCP. It omits `log_file_validation_enabled`: GCP has no
  log file validation feature. The audit-log integrity policies check only trails that report
  the field. With only GCP or Azure trails they pass, and `check` marks them `passed without
  examining any resource`. Whether the locked `_Required` log bucket meets the control is for
  your auditor.

## Azure

### Keys

| Source IDs | Key | Required | Effect |
|---|---|---|---|
| All except `azure.entra` | `subscription_id` | yes | Subscription to read. |
| All except `azure.entra` | `tenant_id` | no | Accepted; not used. |
| `azure.entra` | `tenant_id` | no | Expected tenant. The source reads the credential's home tenant; if `tenant_id` differs, the run stops with exit `3`. |
| `azure.entra` | `subscription_id` | no | Accepted; not used. |

### Credentials

`DefaultAzureCredential`, in this order: environment variables (`AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), workload identity, managed identity, Azure CLI. In CI,
run `azure/login` with OIDC before `sigcomply check`; locally, run `az login`. All `azure.*`
sources share one identity per run, so instances can only vary `subscription_id`.

### Sources

| Source ID | Emits | Role |
|---|---|---|
| `azure.acr` | `container_registry` | Reader |
| `azure.aks` | `kubernetes_cluster` | Reader |
| `azure.backup` | `backup_plan` | Backup Reader or Reader |
| `azure.certs` | `tls_certificate` | Reader |
| `azure.compute` | `compute_instance` | Reader |
| `azure.cosmos` | `nosql_table` | Reader |
| `azure.defender` | `threat_detection_service`, `security_service`, `vulnerability_finding` | Security Reader or Reader |
| `azure.entra` | `directory_user`, `roster_entry`, `password_policy.v2` | Microsoft Graph application permissions (below) |
| `azure.keyvault` | `kms_key`, `secret` | Reader |
| `azure.monitor` | `log_group`, `audit_log_trail` | Reader |
| `azure.network` | `firewall_rule`, `network` | Reader |
| `azure.policy` | `config_change_tracking` | Reader |
| `azure.sql` | `managed_database_instance` | Reader |
| `azure.storage` | `object_storage_bucket` | Reader |

Assign roles on the subscription.

`azure.entra` needs these admin-consented Graph application permissions:

| Emitted type | Permissions | License |
|---|---|---|
| `directory_user` | `User.Read.All`, `AuditLog.Read.All` | Entra ID P1 or P2 |
| `roster_entry` | `User.Read.All` | none |
| `password_policy.v2` | `Domain.Read.All` | none |

### Caveats

- Without `AuditLog.Read.All` or a P1/P2 license, `azure.entra` fails for `directory_user`
  instead of reporting MFA as off. Only policies bound to it get status `error`.
- `azure.entra` `password_policy.v2` has one record per verified domain and carries only
  password expiry. Minimum length, complexity and reuse are not readable through Graph, so those
  policies have nothing to evaluate on an Entra-only estate.
- `azure.entra` `roster_entry` excludes guest users.
- `azure.certs` reads App Service certificates and certificate orders. It does not read Key
  Vault certificates.
- `azure.storage` skips FileStorage (Premium Files) accounts. They have no blob service, so
  they are not object storage.
- `azure.monitor` reports the Activity Log as enabled and subscription-wide, and omits
  `log_file_validation_enabled`: the Activity Log has no log file validation feature. See the
  `gcp.audit` caveat above for how the integrity policies treat that.
- Field caveats for `azure.keyvault`, `azure.cosmos`, `azure.sql` and `azure.monitor` are in
  [Source caveats](#source-caveats).

## GitHub

Source ID: `github`. Emits `git_repository`, `directory_user`, `source_control_org_policy`,
`vulnerability_finding`, `pull_request`, `deployment`.

| Key | Required | Default | Effect |
|---|---|---|---|
| `org` | yes | none | Organization to read. |
| `token` | no | none | API token. Prefer `token_env` or `GITHUB_TOKEN` so the token stays out of the repository. |
| `token_env` | no | none | Name of an environment variable holding the token. An empty or unset variable is an error. |
| `base_url` | no | `https://api.github.com` | API URL for GitHub Enterprise Server. |

Token lookup order: `token`, then `token_env`, then `GITHUB_TOKEN`.

| Token type | Access |
|---|---|
| Classic | `read:org`; `repo` for private repositories; `security_events` to read code scanning on private repositories; `admin:org` to read the org 2FA requirement; `repo_deployment` for deployments |
| Fine-grained | Organization members read; repository Administration, Metadata, Pull requests, Deployments, Checks, Commit statuses, Code scanning alerts, and Dependabot alerts read |

Caveats:

- Members carry no email. Link them to the [identity roster](../guides/identity-roster.md) with
  `experimental.roster.aliases` keyed by login, or list them in `non_human`.
- Archived repositories are skipped: they emit no `git_repository` record, because their settings
  cannot change without unarchiving them. Changes merged into them during the audit period still
  emit `pull_request` records. Forks owned by the organization are read like any other repository.
- Branch protection combines classic branch protection and repository or organization rulesets
  that apply to the default branch. A branch with neither counts as unprotected, with force-push
  allowed, which is GitHub's default.
- `code_scanning_enabled` is true when the repository has at least one code scanning analysis
  (CodeQL default or advanced setup, or an uploaded SARIF file).
- `checks_passed` reads both check runs and commit statuses on the change's head commit.
- A read the source cannot complete (a missing permission, a rate limit, a server error) fails
  the source, and the policies bound to it report `error`. The source never reads a failed
  request as a setting that is off.
- `pull_request` and `deployment` list only changes merged and deployments created in the audit
  period. Each merged change costs four API calls (details, reviews, check runs and commit
  status) on top of the listing pages, and each deployment one. Every policy bound to the source
  collects again, so a run costs that many calls once per bound policy, against GitHub's 5,000
  requests per hour for a token (1,000 for `GITHUB_TOKEN` in Actions). A large organization can
  hit the limit; the affected policies then report `error`.
- The organization's Dependabot alerts are read as none only when GitHub answers that alerts are
  disabled. A token without access makes the vulnerability policies report `error`.
- The org 2FA requirement needs `admin:org`. See [Source caveats](#source-caveats).

## GitLab

Source ID: `gitlab`. Emits `git_repository`, `directory_user`, `pull_request`, `deployment`.

| Key | Required | Default | Effect |
|---|---|---|---|
| `group` | yes | none | Group ID or full path (`my-group/sub-group`). Projects in subgroups are included; projects other groups share into it are not. |
| `token` | no | none | Personal, group, or project access token. Prefer `token_env` or `GITLAB_TOKEN`. |
| `token_env` | no | none | Name of an environment variable holding the token. An empty or unset variable is an error. |
| `base_url` | no | `https://gitlab.com` | URL of a self-managed instance. |

Token lookup order: `token`, then `token_env`, then `GITLAB_TOKEN`. The token needs the `read_api`
scope, and its user needs Maintainer on each project to read the default branch's protection. If
that read is refused, the source stops with an error rather than report force pushes as
forbidden. A default branch with no protection rule is reported as unprotected, with force pushes
allowed, which is GitLab's behaviour. Member MFA is readable only by an instance-admin token on
self-managed GitLab.

Caveats:

- Seven fields depend on tier or token privilege, or have no API. See
  [Source caveats](#source-caveats).
- On Free tier, approval rules read as zero required approvals. The approver list is readable on
  Free, and GitLab records no approval time, so an approval counts as before the merge.
- Member email is returned only to privileged tokens, so `email` may be absent.
- `directory_user` lists the members of the configured group: direct members, members inherited
  from its parent groups, and invited groups. People who are members only of a subgroup or of a
  single project are not listed, so MFA and admin policies do not cover them.
- On gitlab.com every member reads `mfa_enabled: false`, so MFA policies bound to GitLab fail.
  Bind those policies to your identity provider with `bindings:`, or enable the group's "Require
  two-factor authentication" setting and record an exception.

## Okta

Source ID: `okta`. Emits `directory_user`, `roster_entry`, `password_policy.v2`, `okta_app`.

| Key | Required | Default | Effect |
|---|---|---|---|
| `org_url` | yes | none | Tenant URL, for example `https://acme.okta.com`. It must use `https` and have no path; any other value stops the run with exit `3`. |
| `api_token` | no | none | API token, sent with the `SSWS` scheme. Prefer `token_env` or `OKTA_API_TOKEN`. |
| `token_env` | no | none | Name of an environment variable holding the token. An empty or unset variable is an error. |

Token lookup order: `api_token`, then `token_env`, then `OKTA_API_TOKEN`.

An `SSWS` API token acts with its owner's admin role. The owner must be able to read:

| Emitted type | What the owner reads | OAuth scope equivalent |
|---|---|---|
| `directory_user` | users and their admin role assignments (for `is_admin`) | `okta.users.read`, `okta.roles.read` |
| `roster_entry` | users | `okta.users.read` |
| `password_policy.v2` | password policies; a read-only administrator role works, `ORG_ADMIN` is the fallback | `okta.policies.read` |
| `okta_app` | applications (`/api/v1/apps`) | none listed in the code |

Caveats:

- `is_admin` comes from directly assigned admin roles. A user who is an admin only through a
  group may read as not admin.
- `is_active` is true for `ACTIVE`, `RECOVERY`, `PASSWORD_EXPIRED` and `LOCKED_OUT`.
- `mfa_enabled` is true when the user has at least one active factor other than a security
  question or email. A security question is a second password, and email proves no specific
  device (NIST SP 800-63B). SMS and voice still count.
- `password_policy.v2` has one record per active password policy. A 403 on the policy read is a
  collection error, not "no policies".
- Users deleted from Okta do not appear in the roster.

## Active Directory

Source ID: `active_directory`. Emits `roster_entry` only; it exists to be the
[identity roster](../guides/identity-roster.md).

| Key | Required | Default | Effect |
|---|---|---|---|
| `url` | yes | none | `ldaps://host` (port 636), or `ldap://host` (port 389) only with `start_tls: true`. |
| `bind_dn` | yes | none | DN of the read-only bind user. |
| `bind_password` | no | none | Bind password. Prefer `token_env` or `SIGCOMPLY_AD_BIND_PASSWORD`. Anonymous binds are rejected. |
| `token_env` | no | none | Name of an environment variable holding the bind password. An empty or unset variable is an error. |
| `start_tls` | no | `false` | Bool. Upgrade an `ldap://` connection with StartTLS. |
| `base_dn` | no | the RootDSE `defaultNamingContext` | Search base. Must parse as a DN. |
| `user_filter` | no | `(&(objectCategory=person)(objectClass=user))` | LDAP filter for user objects. |
| `page_size` | no | `500` | Integer, clamped to 1 to 1000. |
| `timeout` | no | `30s` | Duration string or whole seconds. Applies to the dial, the TLS handshake, and each request. |
| `ca_cert` | no | system roots | Path to a PEM CA certificate. |
| `tls_server_name` | no | the URL host | Name to verify on the server certificate. Set it when `url` uses an IP address. |
| `service_account_ous` | no | none | List of DNs. Accounts at or under one are marked as service accounts. |

Password lookup order: `bind_password`, then `token_env`, then `SIGCOMPLY_AD_BIND_PASSWORD`.
A wrong value type is a config error (exit `3`). All checks run before connecting.

Caveats:

- TLS 1.2 or later is required and the certificate is always verified. There is no skip-verify
  option.
- Use a dedicated non-admin bind user; Authenticated Users can read the attributes the source
  needs.
- Domain controllers are rarely reachable from hosted CI runners. Run on a runner inside the
  network or over a VPN.
- Deleted accounts (tombstones) are not read, so they do not appear in the roster.
- An `active_directory[...]` instance cannot be the roster source.

## Manual evidence

Source ID: `manual.pdf`. Emits `signed_document`. One per project; it takes no `[instance]`
suffix. If it is not configured and the run would collect a manual policy, `check` stops before
collecting with a config error (exit `3`) that names `sources.manual.pdf`. A run with no manual
policy to collect (all automated, carried forward, or excepted as a whole) does not need it.

| Key | Required | Default | Effect |
|---|---|---|---|
| `backend` | no | `local` | `local`, `s3`, `gcs` or `azure_blob`. |
| `prefix` | no | `manual/` | Folder prefix in the bucket. A missing trailing `/` is added. |
| `path` | `local` | none | Directory that holds the evidence folders. |
| `bucket` | `s3`, `gcs` | none | Bucket name. For `local`, defaults to `path`. |
| `region` | `s3`, unless `vault.region` is set | `vault.region` | Bucket region. |
| `endpoint` | no | none | `s3` only: URL of an S3-compatible store. |
| `force_path_style` | no | `false` | `s3` only: `true` or `false` (quoted or not), path-style addressing for S3-compatible stores. Any other value is a config error (exit `3`). |
| `account` | `azure_blob` | none | Storage account name. |
| `container` | `azure_blob` | none | Container name. |

Credentials come from the backend's provider chain, the same as the matching `aws.*`, `gcp.*` or
`azure.*` sources. The source needs list and read access on the prefix; for `s3` that is
`s3:ListBucket` and `s3:GetObject`. The `s3` vault needs `s3:ListBucket`, `s3:GetObject` and `s3:PutObject`.

The CLI reads `{prefix}{evidence_catalog_id}/{period_id}/`, checks that a supported file is
present and was uploaded in the entry's cadence window, merges the files into one PDF to validate
them, and signs a record that carries each file's hash and the merged PDF's hash. It stores the
merged PDF in the vault's run folder, listed in the signed run manifest. It does not read what
the documents say. Folder layout and file types:
[Manual evidence](../guides/manual-evidence.md).
