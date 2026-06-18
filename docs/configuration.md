# Configuration Guide

SigComply CLI can be configured through three sources, listed from lowest to highest priority:

1. **Config file** (`.sigcomply.yaml`) — the primary source: framework, vault, sources, bindings.
2. **Environment variables** (`SIGCOMPLY_FRAMEWORK` plus provider credentials).
3. **CLI flags** (run-mode and cloud flags — see [CLI Flags](#cli-flags)).

Higher-priority sources override lower ones where they overlap. Note the
flag surface is narrow: most settings (framework, storage, sources) are
config-only. For the framework specifically, `SIGCOMPLY_FRAMEWORK=soc2`
beats `framework:` in the config; there is no `--framework` flag on `check`.

---

## Project model

**One project = one repository = one framework.** A project is the
GitHub or GitLab repo you run `sigcomply` in. Its `.sigcomply.yaml`
declares exactly one framework via the singular `framework:` key — not
a list. There is no `frameworks:` field.

Customers pursuing multiple frameworks (SOC 2 + ISO 27001, SOC 2 +
HIPAA) use **multiple repositories**, one per framework — each with
its own config, CI workflow, and evidence vault. Multi-framework
inside a single repo is not the supported configuration: it creates
ambiguity at the CI scheduling layer (which framework's cadence does
the daily workflow run?) and complicates auditor review.

See [`docs/architecture/01-conceptual-model.md`](architecture/01-conceptual-model.md)
§12 for the full definition.

---

## Quick Start

```bash
# A config file is required (it selects the framework, vault, and sources).
cat > .sigcomply.yaml <<EOF
schema_version: project.v1
framework: soc2
vault:
  backend: local
  path: ./.sigcomply/vault
sources:
  aws.iam: { region: us-east-1 }
  github:  { org: my-org }
EOF

# Provide credentials via the provider's normal env vars, then run:
export GITHUB_TOKEN=ghp_...
sigcomply check
```

---

## Source configuration reference

Every source is keyed by its **source ID** under `sources:`; the value is
that source's config map. The table below is the at-a-glance reference for
**which config keys each source takes** and **how it authenticates** —
the per-source detail (IAM roles / OAuth scopes / Graph permissions, field
mappings, honest gaps) follows under [Credentials](#credentials) and the
per-provider sections. For *which evidence type each source emits*, see the
provider × evidence-type matrix in
[`architecture/04-source-plugins.md`](architecture/04-source-plugins.md).

Credentials are **never** config keys — they always come from the
provider's ambient credential chain (env vars, IAM roles, ADC, OIDC /
workload-identity federation). The keys below only identify *what* to scan
(account / project / subscription / org), never *how* to authenticate.

| Source ID(s) | Required keys | Optional keys | Credential chain |
|--------------|---------------|---------------|------------------|
| **`aws.*`** — all 23 AWS sources (`aws.iam`, `aws.s3`, `aws.ec2`, `aws.rds`, `aws.kms`, `aws.cloudtrail`, `aws.config`, `aws.dynamodb`, `aws.ecr`, `aws.eks`, `aws.acm`, `aws.backup`, `aws.cloudwatch`, `aws.guardduty`, `aws.inspector`, `aws.lambda`, `aws.secretsmanager`, `aws.vpc`, `aws.iam_access_key`, `aws.password_policy`, `aws.security_alert`, `aws.security_group`, `aws.security_services`) | — | `region` | AWS SDK default chain (env → profile → IAM role → OIDC/IRSA); `region` falls back to `AWS_REGION` then the SDK default |
| **`gcp.*`** — project-scoped (`gcp.compute`, `gcp.iam`, `gcp.sql`, `gcp.storage`, `gcp.firewall`, `gcp.network`, `gcp.kms`, `gcp.secretmanager`, `gcp.logging`, `gcp.audit`, `gcp.asset`, `gcp.artifactregistry`, `gcp.gke`, `gcp.firestore`, `gcp.backup`, `gcp.certs`) | `project_id` | — | Application Default Credentials (ADC) |
| `gcp.directory` | — | `customer_id` (defaults to the `my_customer` alias) | ADC — Admin SDK Directory API; needs a Workspace-admin context (account/customer-scoped, **not** project-scoped) |
| `gcp.scc` | `organization_id` | — | ADC — Security Command Center; **org-scoped**, needs org-level SCC IAM |
| **`azure.*`** — ARM plane, all except `azure.entra` (`azure.storage`, `azure.sql`, `azure.network`, `azure.compute`, `azure.keyvault`, `azure.monitor`, `azure.defender`, `azure.acr`, `azure.aks`, `azure.cosmos`, `azure.backup`, `azure.certs`, `azure.policy`) | `subscription_id` | — | `DefaultAzureCredential` (env → managed identity → Azure CLI → OIDC federation) |
| `azure.entra` | — | `tenant_id` | `DefaultAzureCredential` — Microsoft Graph plane (directory/tenant-scoped) |
| `github` | `org` | — | `token` config key or `GITHUB_TOKEN` env |
| `gitlab` | `group` | `base_url` (self-managed; default `https://gitlab.com`) | `token` config key or `GITLAB_TOKEN` env |
| `okta` | `org_url` | — | `api_token` config key or `OKTA_API_TOKEN` env |
| `manual.pdf` | per backend: `local`→ none (defaults to local FS); `s3`→ `bucket`, `region`; `gcs`→ `bucket`; `azure_blob`→ `account`, `container` | `backend` (default `local`), `prefix`, plus `endpoint` + `force_path_style` (on-prem `s3`) | the selected backend's own chain (matches `aws.*` / `gcp.*` / `azure.*`) |

> The five AWS sources whose **source ID differs from their package
> directory** are `aws.iam_access_key` (dir `accesskeys`),
> `aws.password_policy` (dir `passwordpolicy`), `aws.security_alert` (dir
> `securityalert`), `aws.security_group` (dir `securitygroups`), and
> `aws.security_services` (dir `securityservices`). Use the dotted ID in
> `.sigcomply.yaml`, never the directory name.

---

## Credentials

Credentials are **never** stored in the config file. They come from environment variables
or ambient credential sources (IAM roles, OIDC).

### AWS

The CLI uses the standard [AWS SDK credential chain](https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/). No SigComply-specific configuration needed.

| Method | When to Use | Setup |
|--------|-------------|-------|
| **Environment variables** | Local development | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| **AWS CLI profile** | Local development | `aws configure`, then `AWS_PROFILE=name` |
| **IAM role** | EC2, ECS, Lambda | Attach role to instance/task — no env vars needed |
| **OIDC / IRSA** | GitHub Actions, EKS | Configure OIDC provider + role trust policy |

**Minimum IAM permissions required:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListAttachedGroupPolicies",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "s3:ListAllMyBuckets",
        "s3:GetBucketVersioning",
        "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### GitHub

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Yes (if using GitHub collector) | Personal access token or GitHub App token |

**Required token scopes:** `read:org`, `repo` (for private repos), `admin:org` (for 2FA status visibility).

The token is read in the GitHub collector's `Init()` method. If `GITHUB_TOKEN` is not set and no token is provided via `WithToken()`, initialization fails with a clear error.

### GitLab

| Variable | Required | Description |
|----------|----------|-------------|
| `GITLAB_TOKEN` | Yes (if using GitLab collector) | Personal-access or group-access token, or set `token` in config |

Config keys (under `sources.gitlab`): `group` (group ID or full path, e.g. `my-group/sub-group`) is required; `token` may be supplied here or via `GITLAB_TOKEN`; `base_url` is optional and targets a self-managed instance (default `https://gitlab.com`). A complete worked example — one `gitlab` source supplying both `git_repository` and `directory_user`, bound to real SOC 2 policies on a self-managed instance — is at [`docs/architecture/examples/gitlab-selfmanaged.sigcomply.yaml`](architecture/examples/gitlab-selfmanaged.sigcomply.yaml).

**Required token scope:** `read_api`. The collector enumerates the group's projects (`include_subgroups`) and emits one `git_repository` record per project — substitutable for GitHub repositories in every branch-protection / code-review policy. Per project it reads branch-protection, approval-rule, approval-config, and push-rule state. It also lists the group's members and emits one `directory_user` record per member — substitutable for GitHub / Okta / AWS IAM identities in every MFA / admin / lifecycle policy. Mapping: `is_admin` ← group role ≥ Maintainer **or** instance admin; `is_active` ← member state `active`; `mfa_enabled` ← the user's `two_factor_enabled`; `id`/`identity_key` ← username.

**Known limitations (v1):** some signals are premium/ultimate features and degrade gracefully to `false` on free tier (the endpoint 404s): `requires_signed_commits` (push rule `reject_unsigned_commits`) and `require_code_owner_reviews`. Pipeline SAST / Secret Detection / Dependency scanning have **no read-only project-settings API** (they are configured in `.gitlab-ci.yml`), so `secret_scanning_enabled`, `code_scanning_enabled`, and `dependabot_alerts_enabled` are always emitted as `false`; `push_protection_enabled` maps to GitLab's pre-receive secret detection. For `directory_user`, `mfa_enabled` and instance-admin status are only readable with a **group-owner / instance-admin token** (via the Users API); with a lesser-privileged token the per-member read is forbidden and `mfa_enabled` is best-effort `false` — provision an owner/admin token where MFA-enforcement policies matter. Member email is likewise only exposed to elevated tokens, so the optional `email` field may be omitted.

### Okta

| Variable | Required | Description |
|----------|----------|-------------|
| `OKTA_API_TOKEN` | Yes (if using Okta collector) | Okta admin API token (sent via the `SSWS` scheme), or set `api_token` in config |

Config keys (under `sources.okta`): `org_url` (the full tenant URL, e.g. `https://acme.okta.com`) is required; `api_token` may be supplied here or via `OKTA_API_TOKEN`.

**Required privileges:** the token owner must be able to **read user role assignments** (an admin token, or the `okta.roles.read` OAuth scope) so the collector can populate `is_admin` on each `directory_user` from `GET /api/v1/users/{id}/roles`. Without it, the directory_user records still emit but `is_admin` is unreliable — which makes the admin-MFA policies error rather than evaluate.

**Known limitation (v1):** `is_admin` is derived from **directly-assigned** admin roles. A user who is an administrator *only* through a group-role assignment may read as `is_admin=false`; group-inherited admin resolution is deferred. The roles call is per-user (N+1 over the user list) and draws from Okta's org-wide `/api/v1/users/*` rate-limit bucket.

### GCP

GCP sources use [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) (ADC) — no SigComply-specific credential config. Set ADC up in your CI workflow (`google-github-actions/auth` via Workload Identity Federation, or `gcloud auth application-default login` locally) before running `sigcomply check`. Project-scoped GCP sources (`gcp.storage`, `gcp.iam`, `gcp.compute`, `gcp.sql`, and the rest) take a `project_id` config key; the two exceptions are `gcp.directory` (account/customer-scoped — `customer_id`) and `gcp.scc` (organization-scoped — `organization_id`). A full worked GCP-only SOC 2 config — the gcp.* source family covering identity, network, encryption, logging, change-tracking, and security posture, with the password-policy controls deferred to manual evidence (see WU-0.3) — lives at [`docs/architecture/examples/gcp-project.sigcomply.yaml`](architecture/examples/gcp-project.sigcomply.yaml).

The `gcp.directory` source is the exception: it reads Google Workspace / Cloud Identity users via the **Admin SDK Directory API**, which is **account/customer-scoped, not project-scoped**. Config keys (under `sources.gcp.directory`): `customer_id` is optional and defaults to the `my_customer` alias (resolves to the credential's own organization); set it to an explicit `C0...` customer ID only to target a different account.

It enumerates all users and emits one `directory_user` record each — substitutable for AWS IAM / Okta / GitHub / GitLab identities in every MFA / admin / lifecycle policy. Mapping: `mfa_enabled` ← the user's 2-step-verification enrollment (`isEnrolledIn2Sv`); `is_admin` ← super-admin **or** delegated admin; `is_active` ← not `suspended`; `id` ← the directory user id; `email`/`identity_key` ← `primaryEmail`; `display_name` ← full name.

**Required scope & privilege:** the read-only scope `https://www.googleapis.com/auth/admin.directory.user.readonly`. The Admin SDK has **no anonymous service-account access** — the ADC identity must be a Workspace admin, or a service account with **domain-wide delegation** authorized for that scope and impersonating an admin subject. Without an admin context the API returns 403 and the source errors. Per-user 2SV enrollment is only meaningfully populated for users in the customer's own domain(s).

The `gcp.firewall` source is project-scoped (`project_id` required, under `sources.gcp.firewall`). It lists VPC firewall rules via the Compute `firewalls.list` API (read-only scope `https://www.googleapis.com/auth/compute.readonly`) and emits one `firewall_rule` record per protocol/port-range — the same neutral type as `aws.security_group`, so network-exposure policies (open ports, unrestricted-source) span both clouds with no policy change. A GCP firewall holds either an `allowed` or a `denied` set; the plugin flattens each into individual rules. Mapping: `direction` ← `INGRESS`/`EGRESS` (lowercased); `protocol`/`from_port`/`to_port` ← each allowed/denied entry's protocol and port range (empty ports ⇒ all ports, `from_port = -1`); `is_unrestricted_ipv4`/`_ipv6` ← `0.0.0.0/0` / `::/0` in the direction's range list (`sourceRanges` for ingress, `destinationRanges` for egress); GCP extras `action` (allow/deny), `network`, `priority`, `disabled` ride in `additionalProperties`.

The `gcp.network` source is project-scoped (`project_id` required, under `sources.gcp.network`). It lists VPC Networks via the Compute `networks.list` API (read-only scope `https://www.googleapis.com/auth/compute.readonly`) and emits one `network` record per VPC — the same neutral type as `aws.vpc`, so flow-logging and default-VPC-removal policies span both clouds with no policy change. Mapping: `id`/`name` ← network name; `is_default` ← network named `default` (GCP exposes no isDefault flag; the default VPC is identified by convention); `cidr_block` ← `IPv4Range` (set only for deprecated legacy networks). **`flow_logs_enabled` is aggregated from subnetworks:** VPC Flow Logs are a per-subnetwork property in GCP (`Subnetworks.aggregatedList`, reading `logConfig.enable` with the legacy `enableFlowLogs` as fallback), so the network-level bool is `true` only when the network has at least one subnetwork **and every subnetwork has flow logs enabled** — a single un-logged subnet (or zero subnets) reports `false`, matching the "all traffic is logged" intent. GCP extras `auto_create_subnetworks` (auto- vs custom-mode), `routing_mode`, `is_legacy`, and `subnet_count` (makes the flow-logs aggregation auditable) ride in `additionalProperties`. Networks are global in GCP, so there is no `region` field.

The `gcp.kms` source is project-scoped (`project_id` required, under `sources.gcp.kms`). It lists Cloud KMS crypto keys via the CloudKMS API (scope `https://www.googleapis.com/auth/cloudkms` — Cloud KMS has no narrower read-only scope) and emits one `kms_key` record per key — the same neutral type as `aws.kms`, so key-rotation policies span both clouds with no policy change. Cloud KMS keys are organized project → location → keyRing → cryptoKey, so the plugin walks all locations (including `global`) and flattens the keys. Mapping: `key_id` ← the cryptoKey full resource name; `is_customer_managed` ← always `true` (every key `cryptoKeys.list` returns is customer-managed — Google's default encryption keys are not surfaced); `key_manager` ← `CUSTOMER` (matches `aws.kms`); `rotation_enabled` ← whether a `rotationPeriod` is set (only `ENCRYPT_DECRYPT` keys support it; asymmetric/MAC keys report `false`); `enabled` ← the primary version state is `ENABLED` (best-effort `true` for keys without a primary). GCP extras `provider`, `purpose`, `protection_level` (SOFTWARE/HSM/EXTERNAL), `rotation_period_days`, and `primary_state` ride in `additionalProperties`.

The `gcp.secretmanager` source is project-scoped (`project_id` required, under `sources.gcp.secretmanager`). It lists Secret Manager secrets via the Secret Manager API (scope `https://www.googleapis.com/auth/cloud-platform` — Secret Manager has no narrower read-only scope; restrict access at the IAM layer with `roles/secretmanager.viewer`, which grants both `secrets.list` and `versions.list`) and emits one `secret` record per secret — the same neutral type as `aws.secretsmanager`, so secrets-rotation and secrets-encryption policies span both clouds with no policy change. Because GCP exposes **no last-rotation timestamp on the secret resource**, the plugin lists each secret's versions to derive the rotation signals (one extra `versions.list` call per secret). Mapping: `id` ← the secret full resource name; `name` ← the trailing secret id; `rotation_enabled` ← a rotation policy is attached (`rotation.nextRotationTime` set — `rotationPeriod` is input-only and does not round-trip); `kms_encrypted` ← a customer-managed KMS key is configured on the replication (checks automatic, per-replica user-managed, and top-level regionalized encryption; absent all three, Google-managed default encryption is reported as `false`, matching `aws.secretsmanager`); `never_rotated` ← the secret has one version (more than one ⇒ it has been rotated); `last_rotated_days` ← days since the newest version's create time (omitted when never rotated). The GCP extra `version_count` (makes the `never_rotated` derivation auditable) rides in `additionalProperties`.

The `gcp.logging` source is project-scoped (`project_id` required, under `sources.gcp.logging`). It lists Cloud Logging log buckets via the Logging API (scope `https://www.googleapis.com/auth/logging.read` — restrict access at the IAM layer with `roles/logging.viewer`, which grants `logging.buckets.list`/`.get`) across all locations (the `-` wildcard) and emits one `log_group` record per bucket — the same neutral type as `aws.cloudwatch`, so log-retention and log-encryption policies span both clouds with no policy change. **Retention mapping differs from AWS:** every GCP log bucket has a finite retention period (no "never expire"), so `retention_set` ← `retentionDays > 0` and `retention_days` ← `retentionDays` — a bucket left at the 30-day `_Default` therefore honestly fails the ≥90-day (SOC 2 CC7.1) and ≥365-day (ISO A.8.15) retention policies, while the system `_Required` bucket (fixed 400 days) passes. Mapping: `id` ← the bucket full resource name (`projects/{project}/locations/{location}/buckets/{bucket}`); `name` ← the trailing bucket id; `kms_encrypted` ← a customer-managed CMEK key is configured (`cmekSettings.kmsKeyName`). GCP extras `location`, `locked` (retention-lock / immutability), `lifecycle_state`, and `kms_key_name` ride in `additionalProperties`.

The `gcp.audit` source is project-scoped (`project_id` required, under `sources.gcp.audit`). It emits **one** `audit_log_trail` record per project — the same neutral type as `aws.cloudtrail`, so the audit-logging policies (SOC 2 CC7.1, ISO A.8.15) span both clouds with no policy change. It models the project-level Cloud Audit Logs posture (not individual log sinks): a sink can route non-audit logs and its absence does not disable audit logging, so the honest analog of an AWS trail is the project itself. Three of the four CloudTrail-shaped fields are emitted as **documented platform constants**, because they are GCP guarantees rather than configurable toggles (the same pattern `gcp.kms` uses for `is_customer_managed`): `is_enabled` ← `true` (Admin Activity audit logs are always-on and cannot be disabled); `is_multi_region` ← `true` (Cloud Audit Logs are global / project-wide — GCP has no per-region trail); `log_file_validation_enabled` ← `true` (integrity is guaranteed structurally — Admin Activity logs route to the locked, immutable `_Required` bucket). Only `kms_encrypted` ← a customer-managed CMEK key is configured on the project's Cloud Logging settings (`cmekSettings.kmsKeyName`; Google-managed default → `false`, matching `aws.cloudtrail`). The plugin makes two read-only calls so the record is grounded in real project state (and fails honestly when access is missing): Cloud Resource Manager `GetIamPolicy` (needs `resourcemanager.projects.getIamPolicy` — `roles/iam.securityReviewer`) and Cloud Logging `GetCmekSettings` (needs `logging.cmekSettings.get` — `roles/logging.viewer`). GCP extras `data_access_logging_enabled` (whether optional Data Access auditing is on for everyone — off by default in GCP; no shipped policy reads it yet), `audited_services` (count), and `kms_key_name` ride in `additionalProperties`.

The `gcp.asset` source is project-scoped (`project_id` required, under `sources.gcp.asset`). It emits **one** `config_change_tracking` record per project — the same neutral type as `aws.config`, so the config-recording policies (SOC 2 CC7.1, ISO A.8.9) span both clouds with no policy change. It models Cloud Asset Inventory **feeds**, not the always-on inventory: Asset Inventory keeps current state + ~35 days of history for every project unconditionally (the analog of AWS's default service-state APIs, *not* of an AWS Config recorder), whereas a Cloud Asset *feed* is the opt-in, deliberately-configured pipeline that publishes real-time configuration-change events to Pub/Sub — the same act as enabling an AWS Config recorder, and the only GCP signal that can honestly be `false`. Mapping (one project-level record, matching `aws.config`'s per-account singleton, so cross-vendor `all`/`none` policies behave identically): `is_recording` ← at least one feed exists (a project with no feeds → `false`, the honest "no change-tracking pipeline configured" finding); `all_resource_types` ← at least one feed is unrestricted by asset type (empty `assetTypes`, or a catch-all `.*`/`*` wildcard — the analog of AWS Config's `allSupported`; a type-scoped feed tracks a subset → `false`); `id` ← `projects/{project}/configChangeTracking` (synthetic and stable — not derived from a feed name, which GCP normalizes to `projects/{number}/feeds/{id}`); `name` ← the project id. It lists feeds via the Cloud Asset Inventory API (`Feeds.List`, single call, no pagination). Cloud Asset Inventory exposes no read-only OAuth scope, so the plugin uses `https://www.googleapis.com/auth/cloud-platform` and relies on the IAM layer for least privilege — grant `roles/cloudasset.viewer` (`cloudasset.feeds.list`). GCP extra `feed_count` (makes the `is_recording` derivation auditable) rides in `additionalProperties`.

The `gcp.scc` source reads **Google Security Command Center** and is **organization-scoped** — it is the one GCP source that takes `organization_id` (under `sources.gcp.scc`), not `project_id`, because SCC tier and per-service enablement are set at the org and findings surface org-wide. The service account needs **org-level** IAM: `roles/securitycenter.findingsViewer` + `roles/securitycenter.settingsViewer` (or `roles/securitycenter.adminViewer`); a project-scoped CI service account that works for the other `gcp.*` sources will likely lack these, so this is the usual setup gotcha. SCC exposes no read-only OAuth scope, so the plugin uses `https://www.googleapis.com/auth/cloud-platform` and relies on IAM for least privilege. It emits **three** cross-vendor types so SCC-backed GCP customers satisfy the same controls as AWS customers with no policy change: (1) `threat_detection_service` (the `aws.guardduty` analog) — one record from Event Threat Detection, `is_enabled` ← ETD `serviceEnablementState == ENABLED`; (2) `security_service` (the `aws.security_services` / Security Hub analog) — one record mapped to `service_type: "siem"` (SCC is GCP's centralized security-findings service, so it satisfies the security-aggregation controls SOC 2 CC7.1 / ISO A.8.16; it is *not* emitted as `cspm`, which no shipped policy reads), `is_enabled` ← Security Health Analytics `serviceEnablementState == ENABLED` (SHA is SCC's foundational detector — its enablement is the readable signal that SCC is actively aggregating findings); (3) `vulnerability_finding` (the `aws.inspector` analog) — one record per **active** finding of class `VULNERABILITY` or `MISCONFIGURATION`, with `severity` mapped to the schema enum (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`, else `INFORMATIONAL`) and `status` from state+mute (`MUTED` → `SUPPRESSED`, `ACTIVE` → `ACTIVE`, else `RESOLVED`). It reads findings via the Security Command Center API (`organizations/{org}/sources/-/findings`, server-side filtered to active vuln/misconfig, paginated) and the two enablement states via the v1beta2 settings API (the only REST surface that exposes `serviceEnablementState`). For each service record the raw `service_enablement_state` rides in `additionalProperties` (so the `is_enabled` derivation is auditable); findings carry `provider` and `finding_class` extras. A finding whose SCC resource wrapper omits a type falls back to `resource_type: "gcp_resource"`.

The `gcp.artifactregistry` source is project-scoped (`project_id` required, under `sources.gcp.artifactregistry`). It lists Artifact Registry repositories via the Artifact Registry API (read-only scope `https://www.googleapis.com/auth/cloud-platform.read-only` — restrict access at the IAM layer with `roles/artifactregistry.reader`, which grants `repositories.list`/`.get` and `.getIamPolicy`) and emits one `container_registry` record per repository — the same neutral type as `aws.ecr`, so scan-on-push, public-exposure, and encryption policies span both clouds with no policy change. Repositories are regional with no all-locations list, so the plugin walks the project's locations (`locations.list`) and lists repositories per location. Mapping: `id` ← the repository full resource name; `name` ← the trailing repository id; `scan_on_push_enabled` ← `vulnerabilityScanningConfig.enablementState == SCANNING_ACTIVE` (the output-only state already combines the per-repo config and the project-level API enablement; a nil config or a non-Docker / unsupported repo → `false`); `image_immutability_enabled` ← `dockerConfig.immutableTags` (Docker repositories only); `is_public` ← the repository IAM policy grants `allUsers` or `allAuthenticatedUsers` (Artifact Registry exposes no public flag, so the plugin makes one `getIamPolicy` call per repository and surfaces a failure rather than silently reporting `false`); `encryption_enabled` ← always `true` (Artifact Registry encrypts every repository at rest — Google-managed default or CMEK — so there is no unencrypted state, matching `aws.ecr`). GCP extras `format` (DOCKER/MAVEN/…), `mode`, `is_customer_managed` (a CMEK `kmsKeyName` is set — the customer-managed-vs-default distinction `encryption_enabled` does not carry), `kms_key_name`, `scanning_state` (the raw scan enablement state), and `registry_uri` ride in `additionalProperties`.

The `gcp.firestore` source is project-scoped (`project_id` required, under `sources.gcp.firestore`). It lists Cloud Firestore databases via the Firestore Admin API (scope `https://www.googleapis.com/auth/datastore` — Firestore exposes no dedicated read-only scope, so restrict access at the IAM layer with `roles/datastore.viewer`, which grants `firestore.databases.list`) and emits one `nosql_table` record per database — the same neutral type as `aws.dynamodb`, so the encryption, point-in-time-recovery, and deletion-protection policies span both clouds with no policy change. One call covers the project: `Projects.Databases.List` over `projects/{project}/databases` returns every database (the `(default)` one plus any named databases) in a single, non-paginated response; if the response reports any `unreachable` location the plugin errors rather than returning a partial list (a silently-dropped database could make an all-quantifier policy falsely pass). Mapping: `id` ← the database full resource name (`projects/{p}/databases/{db}`); `name` ← the trailing database id (`(default)` for the default database); `encryption_enabled` ← always `true` — Firestore encrypts all data at rest unconditionally (Google-managed default keys or a customer CMEK key; there is no unencrypted state), matching `aws.dynamodb`; `point_in_time_recovery_enabled` ← `pointInTimeRecoveryEnablement == POINT_IN_TIME_RECOVERY_ENABLED` (a nil/UNSPECIFIED/DISABLED value → `false`); `deletion_protection` ← `deleteProtectionState == DELETE_PROTECTION_ENABLED`. GCP extras `location`, `database_type` (FIRESTORE_NATIVE/DATASTORE_MODE), `is_customer_managed` (a CMEK `cmekConfig` is set — the customer-managed-vs-default distinction `encryption_enabled` does not carry), `kms_key_name`, `pitr_state`, and `deletion_protection_state` (the raw enums, so an UNSPECIFIED is distinguishable from an explicit DISABLED) ride in `additionalProperties`.

The `gcp.gke` source is project-scoped (`project_id` required, under `sources.gcp.gke`). It lists GKE clusters via the Kubernetes Engine API (read-only scope `https://www.googleapis.com/auth/container.read-only` — restrict access at the IAM layer with `roles/container.viewer`, which grants `container.clusters.list`) and emits one `kubernetes_cluster` record per cluster — the same neutral type as `aws.eks`, so the secrets-encryption, logging, and network-isolation policies span both clouds with no policy change. One call covers the project: `Projects.Locations.Clusters.List` with the all-locations wildcard (`locations/-`) returns both regional and zonal clusters in a single, non-paginated response (the deprecated per-zone path is not used). Mapping: `id` ← the cluster `selfLink` (falls back to `name`); `name` ← the cluster name; `secrets_encryption_enabled` ← `databaseEncryption.state == ENCRYPTED` — this is GKE **Application-layer Secrets Encryption** (Kubernetes `Secret` objects in etcd envelope-encrypted with a customer Cloud KMS key), the thing an auditor judges, *not* etcd-at-rest disk encryption (Google always applies that and it cannot be disabled, so it is not represented); a cluster without the feature → `false`, matching `aws.eks`; `logging_enabled` ← control-plane logging is on (`loggingConfig.componentConfig.enableComponents` is non-empty, or the legacy `loggingService` is set and not `none`); `is_private_endpoint` ← `privateClusterConfig.enablePrivateEndpoint` (control-plane API uses the master's internal IP only); `node_auto_upgrade_enabled` ← every node pool has node auto-upgrade enabled (and at least one pool exists) — the conservative "all nodes are kept patched" reading. GCP extras `location`, `status`, `kms_key_name`, `encryption_state` (the raw desired state) + `current_encryption_state` (the output-only actual state, so a transient `PENDING`/`ERROR` is visible), and `release_channel` ride in `additionalProperties`.

The `gcp.backup` source is project-scoped (`project_id` required, under `sources.gcp.backup`). It lists Backup and DR Service backup plans via the Backup and DR API (scope `https://www.googleapis.com/auth/cloud-platform` — Backup and DR exposes no dedicated read-only scope, so restrict access at the IAM layer with `roles/backupdr.viewer`, which grants `backupdr.backupPlans.list`/`.get`) and emits one `backup_plan` record per plan — the same neutral type as `aws.backup`, so the backup-plan-exists policy (SOC 2 A1.1) spans both clouds with no policy change. Backup and DR Service is GCP's centralized backup product and the direct analog of AWS Backup (it spans Compute, Disk, Cloud SQL, AlloyDB, and Filestore — far broader than the GKE-only Backup-for-GKE service or per-instance Cloud SQL backup toggles, which is why it is the honest mapping). One call covers the project: `Projects.Locations.BackupPlans.List` with the all-locations wildcard (`locations/-`) returns plans from every region, paginated; if the response reports any `unreachable` location the plugin errors rather than returning a partial list. Mapping: `id` ← the plan full resource name (`projects/{p}/locations/{loc}/backupPlans/{plan}`); `name` ← the trailing plan id; `is_active` ← `state == ACTIVE` (Backup and DR exposes a real plan-state enum, unlike `aws.backup`, which reports every listed plan active); `has_retention_rule` ← at least one backup rule has `backupRetentionDays > 0`; `retention_days` ← the maximum `backupRetentionDays` across the plan's rules (omitted when no retention rule exists, matching `aws.backup`); `covers_resource_types` ← the plan's single `resourceType` (e.g. `compute.googleapis.com/Instance`). GCP extras `state` (the raw plan state, so an INACTIVE/CREATING is distinguishable from ACTIVE), `backup_vault`, and `rule_count` (makes the `has_retention_rule` derivation auditable) ride in `additionalProperties`. (A future `gkebackup` source could emit the same `backup_plan` type for GKE workloads — the substitutability the plugin model is designed for.)

The `gcp.certs` source is project-scoped (`project_id` required, under `sources.gcp.certs`). It lists Certificate Manager certificates via the Certificate Manager API (scope `https://www.googleapis.com/auth/cloud-platform` — Certificate Manager exposes no dedicated read-only scope, so restrict access at the IAM layer with `roles/certificatemanager.viewer`, which grants `certificatemanager.certs.list`/`.get`) and emits one `tls_certificate` record per certificate — the same neutral type as `aws.acm`, so the expiry and auto-renewal policies (SOC 2 CC6.7, ISO A.8.21) span both clouds with no policy change. One call covers the project: `Projects.Locations.Certificates.List` with the all-locations wildcard (`locations/-`) returns certificates from every region, paginated; if the response reports any `unreachable` location the plugin errors rather than returning a partial list (a silently-dropped certificate could make an all-quantifier expiry policy falsely pass). Mapping: `id` ← the certificate full resource name (`projects/{p}/locations/{loc}/certificates/{c}`); `domain` ← the first Subject Alternative Name (`sanDnsnames`, populated from `managed.domains` for a managed cert still provisioning); `not_after` ← `expireTime`, normalized to RFC3339 UTC (the durable, replay-safe field); `days_until_expiry` ← whole days from `expireTime` at collect time, rounded toward zero (negative once expired); `is_managed` ← the certificate is managed (`managed` is set, vs. a self-managed uploaded PEM); `auto_renew` ← `true` for managed certificates (Google auto-renews them) and **omitted** for self-managed certs, which have no renewal concept (the auto-renew policy guards on `is_managed`, matching `aws.acm`); `status` ← an honest enum mapping (an expired cert is `EXPIRED`; otherwise a managed cert maps its `managed.state` — ACTIVE→`ISSUED`, PROVISIONING→`PENDING_VALIDATION`, FAILED→`FAILED`, else `INACTIVE` — and a present self-managed cert is `ISSUED`). GCP extras `location`, `san_dns_names` (every covered domain), `managed_state` (the raw managed-cert state), and `scope` (DEFAULT/EDGE_CACHE/ALL_REGIONS/CLIENT_AUTH) ride in `additionalProperties`.

The four **foundation** GCP sources — `gcp.storage` (`object_storage_bucket`, the same neutral type as `aws.s3` / `azure.storage`), `gcp.compute` (`compute_instance`, like `aws.ec2` / `azure.compute`), `gcp.sql` (`managed_database_instance`, like `aws.rds` / `azure.sql`), and `gcp.iam` (`iam_binding`) — predate the per-service documentation convention above but follow the identical model: each is project-scoped (`project_id` required, under `sources.gcp.<service>`), authenticates via ADC, and emits one cloud-neutral record per resource so its policies span all three clouds with no policy change. Restrict access at the IAM layer with the matching read-only role (`roles/storage.viewer`, `roles/compute.viewer`, `roles/cloudsql.viewer`, `roles/iam.securityReviewer`).

### Azure

Azure sources share a single credential and subscription model. The full
Azure source family has shipped — the `azure.entra` directory source plus the
ARM-plane collectors `azure.storage`, `azure.sql`, `azure.network`,
`azure.compute`, `azure.keyvault`, `azure.monitor`, `azure.defender`,
`azure.acr`, `azure.aks`, `azure.cosmos`, `azure.backup`, `azure.certs`, and
`azure.policy` (each documented below). Authentication uses the Azure SDK's
[`DefaultAzureCredential`](https://learn.microsoft.com/azure/developer/go/azure-sdk-authentication)
— no SigComply-specific credential config. The credential resolves through a
chain (environment → workload identity → managed identity → Azure CLI), so:

- **In CI**, run [`azure/login`](https://github.com/marketplace/actions/azure-login)
  with OpenID Connect (set `permissions: id-token: write` and pass
  `client-id`/`tenant-id`/`subscription-id`) **before** `sigcomply check`. The
  action performs the OIDC → Entra token exchange and leaves an Azure CLI
  session that `DefaultAzureCredential` picks up — **no long-lived secret**.
- **Locally**, `az login` (or `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`
  environment variables) works the same way.

#### Workload-identity federation setup (one-time, no secrets)

The CI flow above needs an Entra app registration with a **federated
credential** trusting your CI provider's OIDC issuer — there is no client
secret to store or rotate. One-time setup:

1. **Create an app registration** (or use an existing one) and note its
   **Application (client) ID** and **Directory (tenant) ID**.
2. **Add a federated credential** to it (Entra → App registrations → your app →
   Certificates & secrets → Federated credentials → Add). For GitHub Actions
   pick the "GitHub Actions deploying Azure resources" scenario and scope the
   subject to your repo/branch/environment, e.g.
   `repo:my-org/my-repo:ref:refs/heads/main` (issuer
   `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`).
   For GitLab CI use the GitLab OIDC issuer and a matching subject claim.
3. **Grant read-only RBAC** to that app's service principal: the built-in
   **Reader** role on the subscription (plus **Security Reader** for
   `azure.defender` and **Backup Reader** for `azure.backup`), and the
   Microsoft Graph application permissions for `azure.entra`
   (`User.Read.All`, `AuditLog.Read.All` / `Reports.Read.All`,
   `UserAuthenticationMethod.Read.All`, admin-consented).
4. **Pass** `client-id`/`tenant-id`/`subscription-id` to `azure/login` as shown
   above. No secret is ever stored — the OIDC token is exchanged for a
   short-lived Entra token per run.

Shared config keys (under each ARM-plane `sources.azure.<service>` block):
`subscription_id` is **required** — it scopes resource collection to one
subscription. The Entra/directory source (Microsoft Graph plane) instead takes
an optional `tenant_id` and uses the credential's home tenant by default.
Resource collectors enumerate across resource groups via Azure Resource Graph
(a single fast KQL query per run), and `subscription_id` can be validated or
discovered against the tenant-scoped Subscriptions API. Least privilege is set
at the Azure RBAC layer (e.g. the built-in **Reader** role on the subscription;
some sources need an additional reader role — Security Reader for
`azure.defender`, Backup Reader for `azure.backup` — and `azure.entra`
additionally needs the Microsoft Graph read scopes above). A full worked
Azure-only SOC 2 config — the azure.* source family covering identity, storage,
database, network, compute, encryption, logging, change-tracking, security
posture, container/Kubernetes, NoSQL, backup, and certificates, with the
secret-rotation, audit-log-CMEK, and password-policy controls deferred to
manual evidence — lives at
[`docs/architecture/examples/azure-subscription.sigcomply.yaml`](architecture/examples/azure-subscription.sigcomply.yaml).

#### `azure.entra` — directory_user

Lists Microsoft Entra ID (Azure AD) users via Microsoft Graph and emits one
`directory_user` per user — the same cross-vendor type as `aws.iam`, `okta`,
`github`, `gitlab`, and `gcp.directory`, so MFA / admin / lifecycle policies
evaluate against Entra identities with **zero policy changes**.

```yaml
sources:
  azure.entra:
    tenant_id: 00000000-0000-0000-0000-000000000000  # optional; provenance only
```

`tenant_id` is optional — the Graph token is scoped by the credential's home
tenant (resolved from `azure/login` / `az login` / `AZURE_TENANT_ID`); when set
it tags each record's scope. **No `subscription_id`** (this is a Graph-plane
source, not ARM).

Field mapping (two Graph reads joined on the user object id):

| `directory_user` field | Graph source |
| --- | --- |
| `mfa_enabled` | `userRegistrationDetails.isMfaRegistered` |
| `is_admin` | `userRegistrationDetails.isAdmin` (Microsoft's computed privileged-role flag — no `directoryRoles` traversal) |
| `is_active` | `users.accountEnabled` |
| `email` | `users.mail` **only** (never `userPrincipalName`, which is non-email-shaped for guests; falls back to UPN only as the internal dedup key) |
| `display_name` | `users.displayName` (falls back to UPN) |
| `last_login_at` | `users.signInActivity.lastSignInDateTime` (omitted when unavailable) |

**Required Graph application permissions** (admin-consented on the app
registration): `User.Read.All` + `AuditLog.Read.All`. The
`userRegistrationDetails` report and `signInActivity` both require an **Entra ID
P1 or P2 license**. If those are missing the source returns a clear error
(naming `AuditLog.Read.All` + P1/P2) rather than fabricating `mfa_enabled=false`
for every user — that tags only the Entra-bound policies `error`, never a run
crash. `last_login_at` degrades silently (omitted) when `signInActivity` is
unavailable.

> **Implementation note:** `azure.entra` calls Microsoft Graph over raw REST
> (with a bearer token from `DefaultAzureCredential`), not the
> `microsoftgraph/msgraph-sdk-go` SDK — the Kiota-generated SDK adds minutes to
> build/test/lint and a large transitive tree, against the repo's
> minimal-dependency convention (same reason `github`/`okta` call REST directly).

#### `azure.storage` — object_storage_bucket

Lists every Azure Storage account in the configured subscription and emits one
`object_storage_bucket` per account — the same cross-vendor type as `aws.s3` and
`gcp.storage`, so encryption-at-rest, public-access, and versioning policies
evaluate against Azure with **zero policy changes**.

```yaml
sources:
  azure.storage:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required** (unlike the
Graph-plane `azure.entra`). Collection is two reads per account: the
subscription-wide `Microsoft.Storage/storageAccounts` list, plus a per-account
`blobServices/default` GET for versioning / soft-delete (an N+1; the resource
group is parsed from each account's ARM id for that call).

Field mapping:

| `object_storage_bucket` field | Azure source |
| --- | --- |
| `name` | storage account name |
| `region_or_location` | account `location` |
| `encryption_at_rest_enabled` | **always `true`** — Azure Storage Service Encryption is always-on and cannot be disabled |
| `kms_managed` | `Encryption.keySource == Microsoft.Keyvault` (customer-managed key vs the Microsoft-managed default) |
| `kms_key_id` | resolved Key Vault key identifier when CMEK is configured |
| `public_access_blocked` | `allowBlobPublicAccess == false` (a **nil/absent** value is treated as *not* blocked — an unset value never reads as secure) |
| `versioning_enabled` | blob versioning **OR** blob soft-delete is on (the schema field covers both) |
| `created_at` | account `creationTime` |

The granular `blob_versioning_enabled`, `blob_soft_delete_enabled`,
`soft_delete_retention_days`, `minimum_tls_version`, and `public_network_access`
values ride in `additionalProperties` so the `versioning_enabled` derivation and
security posture stay auditable. A blob-service read failure (e.g. a
missing-permission 403) is surfaced as an error — tagging only the
`azure.storage`-bound policies `error` — rather than silently reporting
`versioning_enabled=false`, which would be misleading false-fail evidence.

**Required RBAC:** the built-in **Reader** role on the subscription
(`Microsoft.Storage/storageAccounts/read` +
`.../storageAccounts/blobServices/read`).

#### `azure.sql` — managed_database_instance

Enumerates Azure's three managed relational-database services in the
subscription and emits one `managed_database_instance` per database/server — the
same cross-vendor type as `aws.rds` and `gcp.sql`, so encryption-at-rest,
public-access, backup, SSL, and multi-AZ policies evaluate against Azure with
**zero policy changes**. One plugin covers all three families (mirroring
`aws.rds`, which covers every engine):

- **Azure SQL** (`armsql`) — one record per database, **excluding** the `master`
  system database. Transparent Data Encryption (TDE) is per-database, so this is
  an N+1+1 walk: list servers → list databases per server → GET TDE per database.
- **PostgreSQL Flexible Server** — one record per server.
- **MySQL Flexible Server** — one record per server.

```yaml
sources:
  azure.sql:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**.

Field mapping:

| `managed_database_instance` field | Azure source |
| --- | --- |
| `id` | the ARM resource id (database id for Azure SQL, server id for the flexible servers) |
| `name` | `server/database` for Azure SQL; the server name for the flexible servers |
| `engine` | `sqlserver` / `postgres` / `mysql` |
| `engine_version` | server `version` |
| `storage_encrypted` | **Azure SQL:** real TDE toggle (`current` TDE state == `Enabled`). **Flexible servers:** **always `true`** — at-rest encryption is always-on and cannot be disabled (the CMEK distinction rides in the `cmek_enabled` extra) |
| `publicly_accessible` | server-level `publicNetworkAccess == Enabled` (on Azure SQL it gates every database on the logical server) |
| `backup_enabled` | **always `true`** — Azure SQL Database always retains automated PITR backups, and the flexible servers always run automated backups (`backup_retention_days` extra makes that auditable) |
| `ssl_required` | **Azure SQL only:** `true` (encrypted connections are enforced unconditionally). **Flexible servers:** **omitted** — SSL enforcement is a server *parameter* (`require_secure_transport`/`ssl`), not a `ServerProperties` field, so rather than fabricate a value the field is left unset and the is_set-guarded SSL policy skips those records |
| `multi_az` | Azure SQL `database.zoneRedundant`; flexible-server `highAvailability.mode == ZoneRedundant` |
| `deletion_protection` | **always `false`** — no Azure managed database exposes a deletion-protection property; the Azure mechanism is an ARM resource lock (`CanNotDelete`), which is not a database property and is not read here |

The `location`, `state`, `public_network_access`, `backup_retention_days`,
`cmek_enabled`, and `minimum_tls_version` values ride in `additionalProperties`.
A list/GET failure (e.g. a missing-permission 403) is surfaced as an error —
tagging only the `azure.sql`-bound policies `error` — rather than silently
reporting an insecure default, which would be misleading false-fail evidence.

> **Deletion-protection / SSL note.** Because `deletion_protection` is always
> `false` and `ssl_required` is omitted for the flexible servers, the SOC 2
> CC7.5 deletion-protection control and the flexible-server SSL control are
> covered via an ARM resource lock plus an exception (or manual evidence)
> rather than by this source.

**Required RBAC:** the built-in **Reader** role on the subscription (read access
to `Microsoft.Sql/servers`, `.../databases`,
`.../databases/transparentDataEncryption`,
`Microsoft.DBforPostgreSQL/flexibleServers`, and
`Microsoft.DBforMySQL/flexibleServers`).

#### `azure.network` — firewall_rule + network

Reads Network Security Groups and Virtual Networks in the subscription and emits
two cross-vendor types: `firewall_rule` (one per NSG rule, flattened — the same
type as `aws.security_group` and `gcp.firewall`) and `network` (one per VNet —
the same type as `aws.vpc` and `gcp.network`), so network-exposure and
flow-logging policies evaluate against Azure with **zero policy changes**.

```yaml
sources:
  azure.network:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**.

**firewall_rule** is produced from each NSG's custom `securityRules`. Only
**Allow** rules are emitted: an NSG Deny rule is the opposite of an exposure, and
the unrestricted-SSH / all-traffic policies do not filter on action, so emitting
a Deny rule open to the internet would false-fail them (Azure estates routinely
carry explicit Deny rules, unlike GCP). The platform `defaultSecurityRules` are
also excluded. Each rule is flattened to one record per destination port range:

| `firewall_rule` field | Azure source |
| --- | --- |
| `id` | `{resourceGroup}/{nsgName}:{direction}:{index}` |
| `name` | `{nsgName} {direction} rule` |
| `group_id` | NSG name |
| `direction` | `Inbound` → `ingress`, `Outbound` → `egress` |
| `protocol` | `Tcp`/`Udp`/`Icmp` → `tcp`/`udp`/`icmp`; `*` → `all` |
| `from_port`/`to_port` | the destination port range (`*` → `-1`/`-1` all-ports; `22` → 22/22; `80-443` → 80/443) |
| `is_unrestricted_ipv4` / `_ipv6` | the direction-relevant address prefixes contain `*`, `Internet`, or `Any` (both) / `0.0.0.0/0` (v4) / `::/0` (v6) |
| `source_cidr` / `dest_cidr` | first source prefix (ingress) / first destination prefix (egress) |

**network** is produced from each VNet:

| `network` field | Azure source |
| --- | --- |
| `id` | VNet ARM resource id |
| `name` | VNet name |
| `region` | VNet `location` |
| `flow_logs_enabled` | an inline **VNet flow log** is enabled |
| `is_default` | **always `false`** — Azure has no provider-created default VNet (unlike an AWS default VPC) |
| `cidr_block` | first `addressSpace.addressPrefixes` entry |

> **Flow-logs note.** `flow_logs_enabled` reflects VNet flow logs (the modern
> signal that supersedes NSG flow logs). NSG-flow-log-only setups (the legacy
> model) are a known v1 gap and read `false` — a conservative mapping (absence is
> treated as "not enabled" rather than guessed true). A list failure (e.g. a
> 403) is surfaced as an error, tagging only the `azure.network`-bound policies.

**Required RBAC:** the built-in **Reader** role on the subscription (read access
to `Microsoft.Network/networkSecurityGroups` and
`Microsoft.Network/virtualNetworks`).

#### `azure.compute` — compute_instance

Lists Virtual Machines in the subscription and emits one `compute_instance`
record per VM — the same cross-vendor type as `aws.ec2` and `gcp.compute`, so
network-exposure, encryption, and monitoring policies evaluate against Azure with
**zero policy changes**.

```yaml
sources:
  azure.compute:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**. The VM
list is requested with `StatusOnly`, which carries each VM's power state in the
single subscription-wide call (no per-VM instance-view round-trip).

| `compute_instance` field | Azure source |
| --- | --- |
| `id` | VM ARM resource id |
| `name` | VM name |
| `region` | VM `location` |
| `is_running` | VM power state is `PowerState/running` (from the instance view) |
| `has_public_ip` | any attached NIC has an IP configuration that references a public IP (one `networkInterfaces` GET per NIC; the public-IP object itself is not resolved — presence of the reference is sufficient) |
| `root_volume_encrypted` | **always `true`** — Azure managed disks are encrypted at rest unconditionally (Storage Service Encryption cannot be disabled) |

Auditable extras (`additionalProperties`): `power_state`, `vm_size`, `os_type`,
`cmek_enabled` (OS-disk `managedDisk.diskEncryptionSet` present → customer-managed
key, vs the platform-managed default), `encryption_at_host`
(`securityProfile.encryptionAtHost`), `kms_key_id` (the disk-encryption-set id),
and `resource_group`.

> **Monitoring gap.** `monitoring_enabled` is **omitted** for Azure VMs: ARM
> exposes no per-VM detailed-monitoring signal comparable to AWS detailed
> monitoring, so a fabricated value would be misleading. The monitoring policies
> guard this field with `is_set` and scope Azure VMs out as a documented coverage
> gap (the same pattern as `gcp.compute`).
>
> **Encryption note.** Because every managed disk is encrypted at rest, the
> root-volume-encryption policy passes for all Azure VMs; the meaningful
> platform/customer-key distinction is surfaced in the `cmek_enabled` extra. A VM
> list or NIC read failure (e.g. a 403) is surfaced as an error — tagging only
> the `azure.compute`-bound policies — rather than fabricating `has_public_ip`.

**Required RBAC:** the built-in **Reader** role on the subscription (read access
to `Microsoft.Compute/virtualMachines` and `Microsoft.Network/networkInterfaces`).

#### `azure.keyvault` — kms_key + secret

Lists Key Vault **keys** and **secret metadata** in the subscription and emits
two cross-vendor types: `kms_key` (one per key — the same type as `aws.kms` and
`gcp.kms`) and `secret` (one per secret — the same type as `aws.secretsmanager`
and `gcp.secretmanager`), so the key-rotation, customer-managed-key, and
secret-rotation/encryption policies evaluate against Azure with **zero policy
changes**.

```yaml
sources:
  azure.keyvault:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**. Everything
is read on the **management plane** (`armkeyvault`) — no Key Vault data-plane
access policies, and the mgmt plane never returns secret values. The keys *list*
endpoint strips the rotation policy, so each key needs a follow-up `Get` (an
N+1).

| `kms_key` field | Azure source |
| --- | --- |
| `key_id` | key ARM resource id |
| `rotation_enabled` | the key's rotation policy has a `rotate` lifetime action with a trigger (a `notify`-only policy reads `false`) |
| `is_customer_managed` | **always `true`** — a Key Vault key is customer-provisioned by definition (matches `gcp.kms`) |
| `key_manager` | **always `"CUSTOMER"`** |
| `enabled` | key attribute `enabled` |

Auditable `kms_key` extras (`additionalProperties`): `protection_level`
(`HSM`/`SOFTWARE`, from the key type's `-HSM` suffix), `key_type` (the `kty`),
`rotation_period` (the rotate trigger's ISO-8601 duration), `vault_name`,
`resource_group`.

| `secret` field | Azure source |
| --- | --- |
| `id` | secret ARM resource id |
| `name` | secret name |
| `rotation_enabled` | **always `false`** — see the note below |
| `kms_encrypted` | **always `true`** — a Key Vault secret is always encrypted at rest by the customer's own vault (the vault *is* the customer-managed key store) |
| `never_rotated` | best-effort: `true` unless the secret has been updated since creation |
| `last_rotated_days` | days since the secret's last update (omitted when never rotated) |

Auditable `secret` extras: `content_type`, `enabled`, `vault_name`,
`resource_group`.

> **Secret-rotation gap.** Azure Key Vault exposes **no API-readable native
> secret-rotation policy** (rotation is implemented externally via Event Grid
> near-expiry events + a Function), so `rotation_enabled` is reported as `false`
> rather than a guessed `true`. The secret-rotation policy therefore flags Azure
> secrets; customers who rotate via automation cover it with a `.sigcomply.yaml`
> exception or manual evidence (the same pattern `azure.sql` uses for
> `deletion_protection`). Because the mgmt plane exposes no secret version
> history, `never_rotated`/`last_rotated_days` are derived from the secret's
> created-vs-updated timestamps (a metadata-only edit also advances "updated", so
> this is an upper bound). A vault/key/secret read failure (e.g. a 403) is
> surfaced as an error — tagging only the `azure.keyvault`-bound policies.

**Required RBAC:** the built-in **Reader** role on the subscription (read access
to `Microsoft.KeyVault/vaults/read`, `.../keys/read`, and `.../secrets/read` —
all management-plane actions Reader includes; no Key Vault access policy needed).

#### `azure.monitor` — log_group + audit_log_trail

Reads Azure Monitor's logging surface in the subscription and emits two
cross-vendor types: `log_group` (one per **Log Analytics workspace** — the same
type as `aws` CloudWatch Logs and `gcp.logging`) and `audit_log_trail` (one per
subscription — the **Activity Log** — the same type as `aws` CloudTrail and
`gcp.audit`), so the log-retention and audit-logging policies evaluate against
Azure with **zero policy changes**.

```yaml
sources:
  azure.monitor:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**.

| `log_group` field | Azure source |
| --- | --- |
| `id` / `name` | Log Analytics workspace ARM id / name |
| `retention_set` | the workspace has a positive `retentionInDays` |
| `retention_days` | the workspace `retentionInDays` (0 when unset) |

Auditable `log_group` extras (`additionalProperties`): `location`, `sku`,
`resource_group`. Log Analytics encryption at rest is platform-always-on;
customer-managed keys (CMEK) are a per-*cluster* feature (a dedicated Azure
Monitor cluster), not a per-workspace property, so `kms_encrypted` is not emitted
in v1 (no `log_group` policy reads it).

| `audit_log_trail` field | Azure source |
| --- | --- |
| `id` | `/subscriptions/{id}/providers/Microsoft.Insights/activityLog` |
| `name` | `"Azure Activity Log"` |
| `is_enabled` | **always `true`** — the Activity Log is always-on and cannot be disabled |
| `is_multi_region` | **always `true`** — subscription-wide across all regions |
| `log_file_validation_enabled` | **always `true`** — the platform Activity Log is append-only / immutable to users (the same platform-integrity basis as `gcp.audit`) |
| `kms_encrypted` | **always `false`** — see the note below |

Auditable `audit_log_trail` extras: `exported` (at least one enabled diagnostic
setting routes the log to a destination), `diagnostic_setting_count`,
`enabled_categories`, `destination_workspace_id`, `destination_storage_account_id`
— read from the subscription's diagnostic settings, which prove whether the
Activity Log is retained beyond the platform's 90-day window.

> **Audit-log CMEK gap.** The native Activity Log platform retention uses
> Microsoft-managed keys, not customer-managed, so `kms_encrypted` is reported as
> `false` rather than a guessed `true`. CMEK would require routing the log (via a
> diagnostic setting) to a CMEK-enabled destination and resolving that
> destination's key state, which is out of scope for v1; customers cover the
> audit-log-encryption control via a routed CMEK destination + a `.sigcomply.yaml`
> exception or manual evidence (the same honest-gap pattern `azure.keyvault` uses
> for secret rotation). A workspace or diagnostic-settings read failure (e.g. a
> 403) is surfaced as an error — tagging only the `azure.monitor`-bound policies.

**Required RBAC:** the built-in **Reader** role on the subscription (covers
`Microsoft.OperationalInsights/workspaces/read` and
`Microsoft.Insights/diagnosticSettings/read`).

#### `azure.defender` — threat_detection_service + security_service + vulnerability_finding

Reads **Microsoft Defender for Cloud** (Azure Security Center) in the
subscription and emits three cross-vendor types: `threat_detection_service` (one
per **Defender plan** — the same type as `aws.guardduty` and `gcp.scc`),
`security_service` (one record for Defender for Cloud itself — the same type as
`aws` SecurityHub/Macie/Inspector and `gcp.scc`), and `vulnerability_finding`
(one per **security sub-assessment** — the same type as `aws.inspector` and
`gcp.scc`), so the threat-detection, security-service-enablement, and
unaddressed-finding policies evaluate against Azure with **zero policy changes**.

```yaml
sources:
  azure.defender:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**. The
Pricings read is shared by `threat_detection_service` and `security_service`, so
it is performed at most once per collection.

| `threat_detection_service` field | Azure source |
| --- | --- |
| `id` / `name` | Defender plan ARM id / plan name (`VirtualMachines`, `StorageAccounts`, `SqlServers`, `Containers`, …) |
| `is_enabled` | the plan's pricing tier is **Standard** (the paid tier with advanced threat detection); the **Free** tier reads `false` |

Auditable `threat_detection_service` extras: `pricing_tier`, `sub_plan`. One
record is emitted **per Defender plan** (mirroring `aws.guardduty`'s
one-record-per-detector granularity), so the "all threat detection enabled"
policy expects every plan on Standard; customers scope out plans for resource
types they do not use via a `.sigcomply.yaml` exception.

| `security_service` field | Azure source |
| --- | --- |
| `id` / `name` | `azure-defender-for-cloud` / `"Microsoft Defender for Cloud"` |
| `service_type` | **always `cspm`** — Defender for Cloud is a Cloud Security Posture Management service (not a SIEM or DLP) |
| `is_enabled` | **at least one Defender plan is on the Standard tier** |

Auditable `security_service` extras: `enabled_plan_count`, `total_plan_count`.
The legacy auto-provisioning toggle is deprecated by Microsoft and is
deliberately **not** used as the enablement signal — a modern estate using
agentless scanning + Defender plans would read a false auto-provisioning value
while being fully protected.

| `vulnerability_finding` field | Azure source |
| --- | --- |
| `id` | the sub-assessment ARM id |
| `resource_id` | the assessed resource's ARM id (`""` for non-Azure resources) |
| `resource_type` | the ARM type parsed from `resource_id` (e.g. `Microsoft.Compute/virtualMachines`), else `azure_resource` |
| `severity` | sub-assessment severity → `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` (anything else → `INFORMATIONAL`) |
| `status` | status code → `Unhealthy`=`ACTIVE`, `Healthy`=`RESOLVED`, `NotApplicable`=`SUPPRESSED`; a missing code → `ACTIVE` (a finding is never silently hidden) |

Auditable `vulnerability_finding` extras: `provider`, `category`. `cve_id` is set
only when the sub-assessment's vulnerability id is a CVE identifier;
`remediation_available` reflects whether the sub-assessment carries remediation
text. A Pricings or sub-assessments read failure (e.g. a 403) is surfaced as an
error — tagging only the `azure.defender`-bound policies.

**Required RBAC:** the built-in **Security Reader** role on the subscription
(covers `Microsoft.Security/pricings/read` and
`Microsoft.Security/assessments/subAssessments/read`); the broader **Reader**
role also suffices.

#### `azure.acr` — container_registry

Lists Azure Container Registries in the subscription and emits one
`container_registry` record per registry — the same cross-vendor type as
`aws.ecr` and `gcp.artifactregistry`, so scan-on-push, public-exposure, and
encryption policies evaluate against Azure with **zero policy changes**.

```yaml
sources:
  azure.acr:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**. Collection
is a single subscription-wide list call (`armcontainerregistry`
`RegistriesClient.NewListPager`) — there is no per-registry follow-up GET.

| `container_registry` field | Azure source |
| --- | --- |
| `id` | registry ARM resource id |
| `name` | registry name |
| `is_public` | `anonymousPullEnabled` — anyone can pull images **without credentials**. (NOT `publicNetworkAccess`, which only means the endpoint is internet-reachable but still requires auth — mapping that would false-fail nearly every registry.) |
| `scan_on_push_enabled` | the **quarantine policy** is enabled — the only per-registry gate that holds pushed images unpullable until scanned. |
| `encryption_enabled` | **always `true`** — ACR always encrypts images at rest (Microsoft-managed keys by default, cannot be disabled) |

Auditable extras (`additionalProperties`): `sku`, `login_server`,
`public_network_access` (the raw `Enabled`/`Disabled` posture),
`anonymous_pull_enabled`, `admin_user_enabled`, `cmek_enabled`
(`encryption.keyVaultProperties` present → customer-managed key vs the
platform-managed default), `kms_key_id`, `encryption_status`, `zone_redundancy`,
`quarantine_policy_status`, and `resource_group`.

> **Scanning gap.** ACR exposes no per-registry "scanning enabled" property:
> image vulnerability scanning is **Microsoft Defender for Containers**, a
> subscription-level capability surfaced by `azure.defender`'s
> `threat_detection_service` (the `Containers` plan), not a registry toggle. The
> quarantine policy is the one per-registry signal that genuinely gates pulls on
> scanning, so `scan_on_push_enabled` reflects it; registries relying on Defender
> for Containers instead cover the scan-on-push controls via a `.sigcomply.yaml`
> exception or manual evidence (the same honest-gap pattern as `azure.keyvault`
> secret rotation). A registry list failure (e.g. a 403) is surfaced as an error —
> tagging only the `azure.acr`-bound policies — rather than fabricating a result.

**Required RBAC:** the built-in **Reader** role on the subscription (read access
to `Microsoft.ContainerRegistry/registries`).

#### `azure.aks` — kubernetes_cluster

Lists Azure Kubernetes Service (AKS) managed clusters in the subscription and
emits one `kubernetes_cluster` record per cluster — the same cross-vendor type as
`aws.eks` and `gcp.gke`, so secrets-encryption, logging, and network-isolation
policies evaluate against Azure with **zero policy changes**.

```yaml
sources:
  azure.aks:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**. Clusters
are listed in one subscription-wide call (`armcontainerservice`
`ManagedClustersClient.NewListPager`); each cluster's audit-logging posture then
needs a per-cluster diagnostic-settings read (`armmonitor`
`DiagnosticSettingsClient`) — an N+1.

| `kubernetes_cluster` field | Azure source |
| --- | --- |
| `id` | cluster ARM resource id |
| `name` | cluster name |
| `secrets_encryption_enabled` | `securityProfile.azureKeyVaultKms.enabled` — Kubernetes Secrets in etcd are encrypted with a customer Key Vault KMS key (the analog of GKE application-layer secrets encryption / EKS envelope encryption). AKS always encrypts etcd with platform keys; this is the customer-controlled signal policies care about. |
| `logging_enabled` | a **diagnostic setting** on the cluster routes an enabled control-plane audit log category — `kube-audit`, `kube-audit-admin`, or `guard` (or the `audit` / `allLogs` category group). |
| `is_private_endpoint` | `apiServerAccessProfile.enablePrivateCluster` — the API server has no public endpoint |
| `node_auto_upgrade_enabled` | `autoUpgradeProfile.upgradeChannel` set to anything other than `none` |

Auditable extras (`additionalProperties`): `resource_group`, `location`,
`power_state`, `provisioning_state`, `sku_tier`, `rbac_enabled`, `network_policy`,
`network_plugin`, `kms_key_id` (the Key Vault KEK id), `disk_encryption_set_id`,
`encryption_at_host` (every agent pool has host encryption), `audit_log_categories`
(the matched categories, making the `logging_enabled` derivation auditable), and
`authorized_ip_range_count`.

> **Logging signal.** AKS control-plane audit logging is **not** a field on the
> cluster object — it is configured through Azure Monitor diagnostic settings on
> the cluster resource (the `kube-audit` family of log categories). The `omsagent`
> (Container Insights) addon was deliberately rejected as a proxy: it collects
> container/metric logs, not the control-plane audit trail this field means. A
> clusters-list or diagnostic-settings read failure (e.g. a 403) is surfaced as an
> error — tagging only the `azure.aks`-bound policies — rather than fabricating a
> result.

**Required RBAC:** the built-in **Reader** role on the subscription (read access
to `Microsoft.ContainerService/managedClusters` and
`Microsoft.Insights/diagnosticSettings`).

#### `azure.cosmos` — nosql_table

Lists Azure Cosmos DB accounts in the subscription and emits one `nosql_table`
record per **account** — the same cross-vendor type as `aws.dynamodb` and
`gcp.firestore`, so encryption, point-in-time-recovery, and deletion-protection
policies evaluate against Azure with **zero policy changes**. Encryption, PITR
and deletion protection are all account-level in Cosmos DB (not per-container),
so one record per account is the right grain (like `gcp.firestore`'s
one-per-database).

```yaml
sources:
  azure.cosmos:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**. Collection
is a single subscription-wide list call (`armcosmos`
`DatabaseAccountsClient.NewListPager`) — there is no per-account follow-up GET.

| `nosql_table` field | Azure source |
| --- | --- |
| `id` | account ARM resource id |
| `name` | account name |
| `encryption_enabled` | **always `true`** — Cosmos DB always encrypts data at rest (Microsoft-managed keys by default, cannot be disabled) |
| `point_in_time_recovery_enabled` | the account's backup policy is **continuous mode** (`ContinuousModeBackupPolicy`, discriminator `Continuous`). Periodic (snapshot-only) and a nil/unknown policy → `false`. |
| `deletion_protection` | **always `false`** — Cosmos DB has no account-level deletion-protection property; an ARM resource lock is the mechanism (a separate plane, not read here) |

Auditable extras (`additionalProperties`): `kind` (`GlobalDocumentDB`/`MongoDB`/…),
`location`, `resource_group`, `backup_policy_type` (`Continuous`/`Periodic`),
`continuous_backup_tier` (`Continuous7Days`/`Continuous30Days`), `cmek_enabled`
(`keyVaultKeyUri` present → customer-managed key vs the platform-managed default),
`kms_key_id`, `public_network_access`, `local_auth_disabled` (`disableLocalAuth`
— Azure AD-only auth), `vnet_filter_enabled`, and `provisioning_state`.

> **Deletion-protection gap.** Cosmos DB exposes no account-level
> deletion-protection toggle; real deletion protection is an **ARM resource lock**
> (`Microsoft.Authorization/locks` — a separate plane, an extra read and N+1, out
> of scope here), so `deletion_protection` is reported `false` rather than
> fabricated `true`. Customers cover that control via a `CanNotDelete` resource
> lock plus a `.sigcomply.yaml` exception or manual evidence — the same honest-gap
> pattern as `azure.sql` deletion protection. An accounts-list failure (e.g. a
> 403) is surfaced as an error — tagging only the `azure.cosmos`-bound policies —
> rather than fabricating a result.

**Required RBAC:** the built-in **Reader** role on the subscription (read access
to `Microsoft.DocumentDB/databaseAccounts`).

#### `azure.backup` — backup_plan

Enumerates Azure Recovery Services **backup protection policies** across the
subscription and emits one `backup_plan` record per policy — the same
cross-vendor type as `aws.backup` and `gcp.backup`, so the backup_plan policy
(`soc2.a1.1.backup_plan_exists`) evaluates against Azure with **zero policy
changes**.

```yaml
sources:
  azure.backup:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**. Collection
is an **N+1 walk**: list every Recovery Services vault in the subscription
(`armrecoveryservices` `VaultsClient.NewListBySubscriptionIDPager`), then list the
backup policies inside each vault (`armrecoveryservicesbackup`
`BackupPoliciesClient.NewListPager`) — protection policies are a child of a vault,
with no subscription-wide list endpoint.

| `backup_plan` field | Azure source |
| --- | --- |
| `id` | policy ARM resource id |
| `name` | policy name |
| `is_active` | the policy currently protects ≥1 item (`ProtectedItemsCount > 0`) |
| `has_retention_rule` | the policy's resolved retention yields a positive day count |
| `retention_days` | the **max** retention across the policy's schedules/sub-policies; omitted when no retention rule |
| `covers_resource_types` | the `BackupManagementType` discriminator (e.g. `AzureIaasVM`/`AzureSql`/`AzureStorage`/`AzureWorkload`) as a 1-element list |

Auditable extras (`additionalProperties`): `location`, `resource_group`,
`vault_name`, and `protected_items_count` (makes the `is_active` derivation
transparent).

> **`is_active` is the honest "actively backing up" signal.** A backup policy has
> no enabled/state flag in Azure — it either exists or not — so a
> defined-but-unused policy (zero protected items) provides no backup coverage and
> reads `is_active=false`. This mirrors `gcp.backup`'s `State==ACTIVE` and is
> stronger than `aws.backup`'s "listed == active" (AWS exposes no such count).
>
> **Retention is approximate.** Azure stores retention as count + unit
> (Days/Weeks/Months/Years), not raw days; Weeks/Months/Years are converted with
> 7/30/365-day approximations. A vault-list or policy-list failure (e.g. a 403) is
> surfaced as an error — tagging only the `azure.backup`-bound policies — rather
> than returning a partial result.

**Required RBAC:** the built-in **Backup Reader** role on the subscription (or the
broader **Reader**) — read access to Recovery Services vaults and their backup
policies.

#### `azure.certs` — tls_certificate

Lists Azure certificates across the subscription and emits one `tls_certificate`
record per certificate — the same cross-vendor type as `aws.acm` and `gcp.certs`,
so the expiry (`soc2.cc6.7.tls_certificates_not_expiring` /
`iso27001.8.21.tls_certificates_valid`) and auto-renewal
(`soc2.cc6.7.tls_auto_renew_enabled` / `iso27001.8.21.tls_auto_renew_enabled`)
policies evaluate against Azure with **zero policy changes**.

```yaml
sources:
  azure.certs:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**. Collection
merges two subscription-wide management-plane reads:

- **App Service certificates** (`armappservice` `CertificatesClient.NewListPager`)
  — TLS certificates uploaded to or Key-Vault-referenced by App Services. These
  are imported (not provider-auto-renewed at this layer): they emit
  `is_managed=false` and **omit** `auto_renew`.
- **App Service certificate orders** (`armcertificateregistration`
  `AppServiceCertificateOrdersClient.NewListPager`) — provider-managed
  certificates (App Service Certificates). These emit `is_managed=true` and a real
  `auto_renew` (the order's `autoRenew` flag).

| `tls_certificate` field | Azure source |
| --- | --- |
| `id` | certificate / order ARM resource id |
| `domain` | App Service cert `subjectName` (else first host name) / order distinguished-name CN |
| `not_after` | cert `expirationDate` / order `expirationTime` (RFC3339 UTC) |
| `days_until_expiry` | derived from `not_after` (negative once expired) |
| `is_managed` | `false` for App Service certs (imported); `true` for certificate orders (provider-managed) |
| `auto_renew` | the order's `autoRenew` flag for managed certs; **omitted** for App Service certs (matching `aws.acm` imported certs) |
| `status` | honest enum: expired → `EXPIRED`; App Service cert maps `valid`/Key Vault secret status, order maps its `CertificateOrderStatus` |

Auditable extras (`additionalProperties`): `name`, `location`, `resource_group`,
and (where present) `issuer`, `thumbprint`, `host_names`, `key_vault_id`,
`key_vault_secret_status`, `product_type`, `provisioning_state`, `serial_number`.

> **Key Vault certificate objects are deliberately not collected here.** A Key
> Vault certificate's expiry and auto-renew (lifetime-action) policy live only on
> the Key Vault **data plane** (`azcertificates`), which needs per-vault access
> policies / RBAC beyond subscription Reader and an N+1 over vaults — breaking the
> ARM-plane / Reader-only model `azure.keyvault` established. Key Vault
> certificate auto-renewal evidence is covered via **manual evidence** (the
> honest-gap pattern `azure.sql` / `azure.keyvault` use). A certificates- or
> orders-list failure (e.g. a 403, or an unregistered
> `Microsoft.CertificateRegistration` provider) is surfaced as an error — tagging
> only the `azure.certs`-bound policies — rather than returning a partial result.

**Required RBAC:** the built-in **Reader** role on the subscription — read access
to App Service certificates and certificate orders.

#### `azure.policy` — config_change_tracking

Emits a single `config_change_tracking` record describing whether the
subscription has resource-configuration tracking configured — the same
cross-vendor type as `aws.config` and `gcp.asset`, so the config-recording
policies (`soc2.cc7.1.config_recording_enabled` /
`soc2.cc7.1.config_all_resource_types` and the `iso27001.8.9` equivalents)
evaluate against Azure with **zero policy changes**.

```yaml
sources:
  azure.policy:
    subscription_id: 00000000-0000-0000-0000-000000000000  # required (ARM plane)
```

This is an **ARM-plane** source, so `subscription_id` is **required**. Azure has
no literal "configuration recorder" on/off toggle (like AWS Config). The
deliberately-configured artifact that makes Azure continuously evaluate and
record the configuration-compliance state of a subscription's resources is an
**Azure Policy assignment** — so an assignment existing is the honest analog of
enabling an AWS Config recorder or creating a GCP Cloud Asset feed. Collection is
a **single subscription-wide list call** (`armpolicy`
`AssignmentsClient.NewListPager`, no N+1) reduced to one record per subscription.

| `config_change_tracking` field | Azure source |
| --- | --- |
| `id` | synthetic `subscriptions/{subscription_id}/configChangeTracking` (stable; never an assignment id) |
| `name` | the subscription id |
| `is_recording` | at least one policy assignment exists (`len(assignments) > 0`) — a fresh subscription with none honestly reports `false` |
| `all_resource_types` | at least one assignment is scoped at the subscription root (`/subscriptions/{id}`). Azure Policy has no per-assignment resource-type list (the analog of AWS Config's `allSupported`), so coverage breadth is approximated by assignment **scope**: subscription-scoped assignments evaluate the whole subscription, RG-scoped ones cover only a subset |

Auditable extras (`additionalProperties`, pure counts — no resource identities):
`assignment_count` (backs `is_recording`), `enforced_count` (assignments in
enforcing `Default` mode vs audit-only `DoNotEnforce`; a nil mode counts as
enforced, the Azure default), `subscription_scoped_count` (backs
`all_resource_types`).

> Compliance-**state** enrichment (counts of compliant/non-compliant resources
> via `armpolicyinsights`) is a deliberate future enhancement — it backs no
> `config_change_tracking` field, and the assignment list alone carries every
> load-bearing signal, so the plugin stays on a single SDK (`armpolicy`). An
> assignments-list failure (e.g. a 403) is surfaced as an error — tagging only
> the `azure.policy`-bound policies — rather than fabricating a result.

**Required RBAC:** the built-in **Reader** role on the subscription
(`Microsoft.Authorization/policyAssignments/read`).

### SigComply Cloud (Paid Tier)

The CLI authenticates to SigComply Cloud using ephemeral OIDC tokens, automatically detected
in GitHub Actions and GitLab CI. No secrets or API tokens needed — just grant `id-token: write`
permission in your workflow.

---

## Config File (`.sigcomply.yaml`)

The config file holds **non-secret, declarative settings** — what to check and how to report.

### File Location

The CLI searches for config files in this order:

1. `--config /path/to/file.yaml` (explicit flag)
2. `.sigcomply.yaml` in the current working directory
3. `~/.sigcomply.yaml` in the home directory

If no file is found, the CLI uses defaults. This is not an error.

### Full Example

The config is parsed with strict key checking (`yaml.KnownFields(true)`):
an unknown top-level key is a hard error, so the keys below are the
complete, authoritative set. A full annotated reference lives at
[`docs/architecture/examples/acmecorp.sigcomply.yaml`](architecture/examples/acmecorp.sigcomply.yaml).
Worked single-cloud profiles are at
[`gcp-project.sigcomply.yaml`](architecture/examples/gcp-project.sigcomply.yaml),
[`azure-subscription.sigcomply.yaml`](architecture/examples/azure-subscription.sigcomply.yaml),
and [`gitlab-selfmanaged.sigcomply.yaml`](architecture/examples/gitlab-selfmanaged.sigcomply.yaml);
a **multi-cloud** profile that binds AWS, GCP, and Azure identity sources
to the same MFA-policy slot (cross-cloud substitutability) is at
[`multi-cloud-hybrid.sigcomply.yaml`](architecture/examples/multi-cloud-hybrid.sigcomply.yaml).

```yaml
# Schema version — required, currently always project.v1.
schema_version: project.v1

# Compliance framework to evaluate (singular key). Options: soc2, iso27001.
# (hipaa is a placeholder string only and fails at runtime.)
framework: soc2

# Audit period model — how the run's period_id is derived.
period:
  fiscal_calendar:
    type: calendar_quarter        # calendar_quarter | fiscal_year | custom
                                  # (custom requires a periods: list)
  time_basis: commit              # commit | wall_clock

# Evidence vault — where signed envelopes, results, and the run manifest land.
vault:
  backend: s3                     # local | s3 | gcs | azure_blob
  bucket: my-evidence
  region: us-east-1
  prefix: sigcomply/              # trailing slash recommended

# Sources — keyed by plugin id; the value is that plugin's config.
# A source is bound to policy slots via `bindings` (below). Manual
# evidence is one project-level source under the reserved key manual.pdf.
sources:
  aws.iam:        { region: us-east-1 }
  aws.s3:         { region: us-east-1 }
  github:         { org: my-org }        # GitHub-hosted code, OR…
  gitlab:         { group: my-group }    # …GitLab-hosted code (add base_url: for self-managed)
  okta:           { org_url: https://my.okta.com }  # api_token here or OKTA_API_TOKEN env
  gcp.kms:        { project_id: my-project }   # project-scoped gcp.* sources take project_id
  gcp.scc:        { organization_id: "123456789012" }  # gcp.scc is org-scoped (not project_id)
  gcp.directory:  { customer_id: my_customer } # account-scoped (optional; defaults to my_customer)
  azure.storage:  { subscription_id: "00000000-0000-0000-0000-000000000000" }  # ARM-plane azure.* take subscription_id
  azure.entra:    { tenant_id: "11111111-1111-1111-1111-111111111111" }        # Graph-plane; tenant_id optional
  manual.pdf:
    backend: s3                   # local | s3 | gcs | azure_blob
    bucket: my-evidence
    region: us-east-1
    prefix: manual/

# Policies — all per-policy config lives under one object per policy ID:
# bindings, parameters, cadence, evidence_mode, and scoped exceptions.
# Omit a policy entirely to take framework defaults + auto-binding.
policies:
  soc2.cc6.1.mfa_enforced:
    bindings:
      user_directory: [okta, aws.iam]   # narrow the slot to chosen sources
    cadence: hourly                      # override the framework cadence
  soc2.cc6.1.access_key_rotation:
    parameters:
      max_age_days: 60                   # tune a policy parameter
  soc2.cc6.1.access_review_quarterly:
    evidence_mode: manual                # automated <-> manual migration
    catalog_entry: access_review_quarterly
  soc2.cc6.7.waf_in_front_of_web_app:
    exceptions:                          # waivers / N/A, versioned in git
      - state: na                        # waived | na
        reason: "API-only product; no public web app requiring a WAF."

# Controls — control-level decisions (coarse, per-control). not_applicable
# cascades na to every policy mapping to the control.
controls:
  CC6.4:
    applicability: not_applicable
    reason: "Cloud-only; physical security inherited from AWS."
    approved_by: ciso@example.com

# SigComply Cloud submission (OIDC-only; auto-enables in CI).
cloud:
  enabled: true

# Output and CI behavior.
output:
  format: text                    # text | json | junit (json/csv only honored by `report`)
  json_path: ./compliance-report.json
ci:
  fail_on_violation: true         # exit 1 on violations (config-only; no flag)
  fail_severity: high             # info | low | medium | high | critical (config-only; no flag)

# ci_environment — free-form key/value map recorded with the run's
# environment metadata (e.g. a deployment label or pipeline name).
ci_environment:
  deployment: production
```

### Minimal Example

```yaml
schema_version: project.v1
framework: soc2
vault:
  backend: local
  path: ./.sigcomply/vault
```

Everything else uses sensible defaults.

### Top-level keys (authoritative)

The config is parsed with `yaml.KnownFields(true)`, so this is the complete
set of accepted top-level keys (`internal/spec/project_config.go`):

| Key | Shape | Notes |
|-----|-------|-------|
| `schema_version` | string | Required; currently always `project.v1`. |
| `framework` | string | Singular. `soc2` \| `iso27001` (`hipaa` is a stub that fails at runtime). |
| `period` | `{ fiscal_calendar: { type, starts, periods[] }, time_basis }` | `type`: `calendar_quarter` \| `fiscal_year` \| `custom` (custom needs `periods:` of `{id, start, end}`). `time_basis`: `commit` \| `wall_clock`. |
| `vault` | open `{ backend, ... }` mapping | Flat; only `backend` is interpreted, other keys pass through to the backend. See [Storage Backends](#storage-backends). |
| `sources` | map: source id → config | Plugin configs; `manual.pdf` is the reserved manual-evidence singleton. |
| `policies` | map: policy id → `PolicyConfig` | All per-policy config, co-located per ID. `PolicyConfig` = `{ bindings: { slot: [source,...] }, parameters: { param: value }, cadence, evidence_mode, catalog_entry, exceptions: [...] }`. `evidence_mode: manual` requires `catalog_entry`; `automated` forbids it. Each exception is `{ scope: { resource_id, resource_pattern }, state (waived\|na), reason, approved_by, approved_at, expires_at }` — no `policy:` field (the map key is the policy). |
| `controls` | map: control id → `{ applicability, reason, approved_by }` | `applicability`: `applicable` \| `not_applicable`; `not_applicable` requires `reason` and cascades `na` to every policy mapping to the control. |
| `cloud` | `{ enabled, base_url }` | `enabled` is a `*bool` (auto-detected in CI when omitted); `base_url` overrides the endpoint. |
| `output` | `{ format, json_path, verbose }` | `format`: `text` \| `json` \| `junit`. |
| `ci` | `{ fail_on_violation, fail_severity }` | Config-only; no equivalent flags. |
| `ci_environment` | map | Free-form environment metadata recorded with the run. |
| `extensions` | `{ path }` | Overrides extension-discovery path (default `.sigcomply/`). |
| `experimental` | map | Forward-compat escape hatch: not-yet-stable keys live here so a newer config never breaks an older CLI. Ignored by the loader. |

---

## Environment Variables

### SigComply Settings

These are the only `SIGCOMPLY_*` variables the CLI reads. Everything else
(vault, sources, storage backends, manual evidence) is configured in
`.sigcomply.yaml` — there are no `SIGCOMPLY_STORAGE_*`,
`SIGCOMPLY_MANUAL_EVIDENCE_*`, `SIGCOMPLY_POLICIES`, or
`SIGCOMPLY_OUTPUT_FORMAT` variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGCOMPLY_FRAMEWORK` | `soc2` | Compliance framework (overrides `framework:` in the config; overridden by no flag — `check` reads config/env only) |
| `SIGCOMPLY_ID_TOKEN` | — | OIDC ID token for Cloud submission when not injected by the CI provider's native mechanism |
| `SIGCOMPLY_VERSION` | build value | Overrides the reported CLI version (used in CI image builds) |

Storage backends (vault and manual evidence) are configured under
`vault:` and `sources.manual.pdf` in the config file — see
[Storage Backends](#storage-backends) and
[Manual Evidence Sources](#manual-evidence-sources). Credentials always
come from the provider's ambient chain or the OIDC variables below, never
from `SIGCOMPLY_*` keys.

### Provider Credentials (Not SigComply-Specific)

| Variable | Provider | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS | Static access key |
| `AWS_SECRET_ACCESS_KEY` | AWS | Static secret key |
| `AWS_SESSION_TOKEN` | AWS | Temporary session token |
| `AWS_PROFILE` | AWS | Named profile from `~/.aws/credentials` |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | AWS | Default region (used by SDK auto-detect) |
| `GITHUB_TOKEN` | GitHub | Personal access token or app token |
| `OKTA_API_TOKEN` | Okta | Admin API token (SSWS); needs role-read to populate `is_admin` |

---

## Storage Backends

`vault:` and the `sources.manual.pdf:` source share **one flat config
shape** — the same `VaultConfig` struct (`internal/spec/project_config.go`).
There are **no** nested `local:`/`s3:`/`gcs:`/`azure_blob:` sub-blocks: every
field sits directly under the block. Which fields apply depends on `backend`.

```yaml
vault:
  backend: s3                # required: local | s3 | gcs | azure_blob

  # Object-store fields (s3 / gcs / azure_blob):
  bucket: my-evidence        # s3 (required), gcs (required)
  region: us-east-1          # s3 (required)
  prefix: sigcomply/         # all object stores; trailing slash recommended
  account: acmeevidence      # azure_blob (required)
  container: sigcomply       # azure_blob (required)

  # local filesystem:
  path: ./.sigcomply/vault   # local (required)

  # s3-compatible extras (MinIO, Ceph, Dell ECS, NetApp StorageGRID):
  endpoint: https://minio.internal.corp:9000
  force_path_style: true

  # AWS credential selection (optional; otherwise the ambient chain is used):
  profile: sigcomply-evidence
  role_arn: arn:aws:iam::123:role/sigcomply-evidence
```

### Required fields per backend

| `backend`    | Required fields      | Common optional fields                          |
|--------------|----------------------|-------------------------------------------------|
| `local`      | `path`               | `prefix`                                        |
| `s3`         | `bucket`, `region`   | `prefix`, `endpoint`, `force_path_style`, `profile`, `role_arn` |
| `gcs`        | `bucket`             | `prefix`                                        |
| `azure_blob` | `account`, `container` | `prefix`, `endpoint`                           |

### Storage credentials are ambient only

There is **no** storage `auth:` block — no `mode: ambient|oidc`, no
`workload_identity_provider`, no `service_account`, no `tenant_id`/`client_id`.
Storage credentials always come from the provider SDK's ambient credential
chain (env vars, IAM role / instance metadata, GCP ADC, Azure
`DefaultAzureCredential`). The CLI does not itself exchange OIDC tokens for
storage credentials — set those up in your CI workflow (e.g.
`aws-actions/configure-aws-credentials`, `google-github-actions/auth`,
`azure/login`) before running `sigcomply check`. The optional `profile` /
`role_arn` fields above only steer the AWS SDK's own resolution; they are not
a separate auth mode. (OIDC *is* used for SigComply Cloud submission — that is
a different concern, see [SigComply Cloud](#sigcomply-cloud-paid-tier).)

---

## Manual Evidence Sources

Manual evidence — the user-supplied PDFs that prove non-automatable
controls (signed NDAs, training certs, access reviews, …) — is a
**project-level singleton**: one repo = one framework, so there is
exactly one manual-evidence source and one bucket per project. It is
configured under the reserved source key `manual.pdf` (NOT a separate
top-level `manual_evidence` block, and NOT per-framework). Multi-framework
customers use multiple repos, each with its own `manual.pdf` source.

```yaml
sources:
  manual.pdf:
    backend: s3            # local | s3 | gcs | azure_blob
    bucket: my-evidence
    region: us-east-1
    prefix: manual/
    # On-prem S3-compatible stores: add endpoint + force_path_style.
```

The config shape is identical to the vault backend (the same flat
`VaultConfig`; see [Storage Backends](#storage-backends)), including
ambient-only credentials; `manual.pdf` simply points at wherever your users
upload files.

### Folder layout per evidence ID

For each `evidence_catalog_id` in the framework catalog, the CLI scans
the folder:

```
{prefix}{evidence_catalog_id}/{period_id}/
```

Where `{period_id}` matches the entry's frequency:

| Frequency | `{period_id}` example |
|-----------|-----------------------|
| daily | `2026-01-15` |
| weekly | `2026-W03` |
| monthly | `2026-01` |
| quarterly | `2026-Q1` |
| yearly | `2026` |

Upload any number of files to the folder — **any filename is accepted**.
Supported formats: PDF (pass-through), JPEG, PNG, GIF, TIFF, WebP, BMP.
Images are auto-converted to PDF; all files are merged into one before
evaluation. Files with unsupported extensions (e.g. `.docx`) appear as
`unsupported_file_type` failures in the violation message so you know
exactly which file to replace.

### Where do I upload?

When evidence is missing, the CLI surfaces the exact folder URI in the
violation message (e.g.
`s3://my-evidence/manual/quarterly_access_review/2026-Q1/`). To see the
full manual-evidence catalog (every `evidence_catalog_id` and its
metadata), run:

```bash
sigcomply evidence catalog --framework soc2          # human-readable
sigcomply evidence catalog --framework soc2 -o json  # machine-readable
```

(The old `sigcomply evidence path` subcommand was removed; only
`evidence catalog` exists.)

### What the CLI checks on each run

The CLI runs a fixed set of checks on every collection — it does not
inspect PDF contents:

| Check | Failure code | What it catches |
|-------|-------------|----------------|
| At least one file found in the folder | *(file_present=false)* | Missing uploads |
| All files have supported extensions | `unsupported_file_type` | `.docx`, `.xlsx`, etc. |
| Image conversion succeeds | `conversion_failed` | Corrupt or unreadable images |
| PDF merge succeeds | `merge_failed` | Structurally-corrupt individual PDFs |
| Merged file ≥ 100 bytes | `file_too_small` | 0-byte or truncated results |
| Merged file starts with `%PDF-` | `missing_pdf_header` | Wrong file type passed as PDF |
| Merged file contains a `/Page` token | `no_pages` | Header-only or empty PDFs |
| Latest upload timestamp within `[period_start, period_end + grace]` | *(in_temporal_window=false)* | Out-of-window uploads |
| Source file set differs from prior period's | `copy_paste_of_prior_period` | Copy-paste of last period's files |

The CLI deliberately does **not** read PDF contents. It does not check
internal dates, signatures inside the document, attendee lists, or
whether the document matches the policy intent — those are the
auditor's job. See [CLAUDE.md §Manual evidence design contract](../CLAUDE.md)
for the full rationale.

### Bucket-level immutability — required for tamper-resistance

The CLI's per-file Ed25519 signing detects accidental drift and
unilateral PDF swaps. It does **not** defend against a party with
vault write access who regenerates envelope + PDF + manifest together
with a fresh ephemeral keypair — the public key lives inside the
envelope, so any re-signing is cryptographically valid.

For genuine tamper-resistance, configure write-once / version-locked
semantics at the storage layer on the bucket that holds your vault:

- **AWS S3**: Object Lock in **compliance mode** with retention
  matching audit-retention requirements (typically 7 years).
- **Google Cloud Storage**: Bucket Lock with a retention policy +
  Object Versioning.
- **Azure Blob Storage**: Immutable storage with locked time-based
  retention policies.
- **Local filesystem**: not suitable for production audit retention —
  use only for ad-hoc `sigcomply check` runs and ephemeral CI storage.

Without one of these settings, the signing scheme still detects
accidental drift, but cannot defend against deliberate re-signing.
Full rationale: [SECURITY.md §Threat Model](../SECURITY.md).

---

## CLI Flags

Flags have the highest precedence and override both config file and env vars.

This is the complete flag set registered by `sigcomply check`. There is
**no** `--framework`/`-f`, `--output`/`-o`, `--json-output`, `--region`,
`--store`, `--storage-path`, `--storage-backend`, `--github-org`,
`--policies`, `--controls`, `--quiet`, `--service`, `--collector`,
`--fail-on-violation`, or `--fail-severity` flag. Framework comes from
`framework:`/`SIGCOMPLY_FRAMEWORK`; storage from `vault:`/`sources:`;
`fail_on_violation`/`fail_severity` from `ci:` — all in the config file.

```
sigcomply check [flags]

Flags:
  -c, --config string             Path to project config (default ".sigcomply.yaml")
  -v, --verbose                   Verbose logging
      --cloud                     Force cloud submission (requires OIDC)
      --no-cloud                  Disable cloud submission
      --cloud-url string          Cloud base URL override (defaults to cloud.base_url)
      --capture-cloud-payload string  Write the cloud SubmissionPayload to this file
                                       instead of POSTing it (auditor escape hatch)
      --cadence string            Only evaluate policies whose effective cadence matches
                                  (continuous|hourly|daily|weekly|monthly|quarterly|annual)
      --cadences strings          Comma-separated cadence set (intersection match;
                                  'on_push' is the virtual value for the on_push axis)
      --on-push                   Only evaluate policies whose on_push=true
      --pr                        PR-mode: filter to on_push + generous slot retry budget
      --scheduled                 Scheduled-mode: cadence-gated; reads/advances per-policy state
```

`--cadence`, `--on-push`, `--cadences`, `--pr`, and `--scheduled` are
mutually exclusive (Cobra rejects combining them).

---

## Cadence & scheduling

Every policy declares a **cadence** — how often it must be re-
evaluated. The CLI uses cadence to decide, on each run, whether to
re-evaluate the policy or emit a carry-forward result that references
the most recent signed envelope.

### Cadence values

Named cadences:

| Value        | Minimum interval before due |
|--------------|-----------------------------|
| `continuous` | 0 (always due)               |
| `hourly`     | 0 (always due in scheduled mode) |
| `daily`      | 23 hours                     |
| `weekly`     | 6 days 23 hours              |
| `monthly`    | 29 days 23 hours             |
| `quarterly`  | 89 days 23 hours             |
| `annual`     | 364 days 23 hours            |

Custom interval cadence:

```yaml
cadence: every:6h          # six hours since LastPassAt
cadence: every:90m         # ninety minutes
cadence: every:2h30m       # composite duration
```

The minimum interval for `every:<duration>` is 5 minutes — CI runners
cannot meaningfully dispatch faster.

`every:24h` is NOT the same as `daily`. The named cadence has 1h
cron-drift slack baked in; `every:24h` is exactly 24h from
LastPassAt and drifts time-of-day across runs.

### Customer overrides

```yaml
# .sigcomply.yaml
framework: soc2
policies:
  soc2.cc6.1.mfa_enforced_admin:
    cadence: every:6h
  soc2.cc7.2.annual_pentest:
    cadence: annual
```

Overrides are exact-match by policy ID. Unknown IDs are caught at
plan time (with a "did you mean …?" suggestion).

### Run modes and cadence

```bash
# Manual (default): evaluate every in-scope policy. No cadence gating.
sigcomply check

# PR: evaluate on_push policies only. Generous retry budget.
sigcomply check --pr

# Scheduled: gate by cadence. Reads per-policy state shards from the vault.
sigcomply check --scheduled
```

There is no `--policies` flag to force-run individual policies — scope is
controlled by the cadence/`on_push` filter flags above plus the per-policy
state shards. To force a re-evaluation of a specific policy, change its
content (which busts the content-hash) or its cadence.

Per-policy state shards live at
`{vault}/state/{framework}/policies/{policy_id}.json`. The shards
are mutable and never signed — they are scheduling state, not audit
evidence. Loss of the state directory is recoverable: the next run
re-evaluates every policy as first-run, surfacing a loud
`first-run: N policies will evaluate for the first time this run`
warning.

Full design: [`docs/architecture/10-cadence-model.md`](architecture/10-cadence-model.md).

---

## CI/CD Setup

### GitHub Actions

```yaml
name: Compliance Check
on: [push]

jobs:
  compliance:
    runs-on: ubuntu-latest
    permissions:
      id-token: write    # For OIDC authentication
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/SigComplyRole
          aws-region: us-east-1

      - name: Run compliance check
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: sigcomply check
        # GitHub org comes from sources.github.org in .sigcomply.yaml.
        # OIDC token is auto-detected from the GitHub Actions environment.
```

### GitLab CI

```yaml
compliance:
  image: golang:1.25
  variables:
    SIGCOMPLY_FRAMEWORK: soc2
  script:
    - sigcomply check
  artifacts:
    reports:
      junit: report.xml
```

### Environment Variables in CI

Store these as CI secrets (never in code):

| Secret | Where to Set |
|--------|-------------|
| `AWS_ACCESS_KEY_ID` | CI secret (or use OIDC role assumption) |
| `AWS_SECRET_ACCESS_KEY` | CI secret (or use OIDC role assumption) |
| `GITHUB_TOKEN` | CI secret (auto-provided in GitHub Actions) |

Non-secrets go in `.sigcomply.yaml` (framework, sources, vault, GitHub
org, AWS region) or — for the framework only — `SIGCOMPLY_FRAMEWORK`:

| Setting | Where to Set |
|---------|-------------|
| Framework | `framework:` in config, or `SIGCOMPLY_FRAMEWORK` env var |
| GitHub org | `sources.github.org` in config |
| AWS region | `sources.aws.<svc>.region` / `vault.region` in config, or the SDK's `AWS_REGION` |

---

## Precedence Examples

Framework resolution order is `SIGCOMPLY_FRAMEWORK` env var → `framework:`
in the config → built-in default (`soc2`). `check` has no `--framework`
flag, so the env var is the highest-precedence source for the framework.

```bash
# Config file says iso27001, env says soc2
# Result: soc2 (env wins over file)
SIGCOMPLY_FRAMEWORK=soc2 sigcomply check

# Config file says iso27001, no env
# Result: iso27001 (file wins over default)
sigcomply check

# No framework in config, no env
# Result: soc2 (built-in default)
sigcomply check
```
