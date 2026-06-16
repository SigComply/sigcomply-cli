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

GCP sources use [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) (ADC) — no SigComply-specific credential config. Set ADC up in your CI workflow (`google-github-actions/auth` via Workload Identity Federation, or `gcloud auth application-default login` locally) before running `sigcomply check`. Project-scoped GCP sources (`gcp.storage`, `gcp.iam`, …) take a `project_id` config key.

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
  okta:           { domain: my.okta.com }
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
