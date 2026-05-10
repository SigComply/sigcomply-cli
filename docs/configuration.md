# Configuration Guide

SigComply CLI can be configured through three sources, listed from lowest to highest priority:

1. **Config file** (`.sigcomply.yaml`)
2. **Environment variables** (`SIGCOMPLY_*` and provider-specific)
3. **CLI flags** (`--framework`, `--region`, etc.)

Higher-priority sources override lower ones. For example, `--framework iso27001` beats
`SIGCOMPLY_FRAMEWORK=soc2` which beats `framework: soc2` in the config file.

---

## Quick Start

```bash
# Minimal — just have AWS credentials and run:
sigcomply check

# With GitHub:
export GITHUB_TOKEN=ghp_...
sigcomply check --github-org my-org

# With a config file:
cat > .sigcomply.yaml <<EOF
framework: soc2
aws:
  regions: [us-east-1]
github:
  org: my-org
EOF
sigcomply check
```

---

## Credentials

Credentials are **never** stored in the config file. They come from environment variables
or ambient credential sources (IAM roles, OIDC).

### AWS

The CLI uses the standard [AWS SDK credential chain](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials). No SigComply-specific configuration needed.

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
        "iam:GetLoginProfile",
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

```yaml
# Compliance framework to evaluate
framework: soc2                    # Options: soc2, iso27001 (iso27001 is early-stage)

# AWS settings (credentials come from environment / IAM, not here)
aws:
  regions:
    - us-east-1
    - eu-west-1

# GitHub settings (token comes from GITHUB_TOKEN env var, not here)
github:
  org: my-org

# GCP settings (credentials come from ADC / Workload Identity, not here)
gcp:
  project_id: my-gcp-project

# Policy filtering (optional — omit to run all policies)
policies:                            # Run only these policies by name
  - cc6_1_mfa
  - cc6_1_github_mfa
controls:                            # Or run only policies for these control IDs
  - CC6.1
  - CC7.1

# Output settings
output:
  format: text                     # Options: text, json, junit
  verbose: false

# CI/CD behavior
ci:
  fail_on_violation: true          # Exit code 1 on violations
  fail_severity: low               # Minimum severity to fail: low, medium, high, critical

# Evidence storage (used for automated evidence + signed envelopes)
storage:
  enabled: false
  backend: local                   # Options: local, s3, gcs, azure_blob
  local:
    path: ./.sigcomply/evidence
  s3:
    bucket: my-bucket
    region: us-east-1
    prefix: compliance/
    # On-prem S3-compatible (MinIO, Ceph, ECS, StorageGRID) — optional:
    # endpoint: https://minio.internal.corp:9000
    # force_path_style: true
    # auth:                        # Optional; defaults to ambient creds
    #   mode: oidc                 # ambient | oidc
    #   role_arn: arn:aws:iam::123:role/sigcomply-evidence

# Manual evidence (PDFs uploaded by users to a known path).
# Each framework can read from its own backend.
manual_evidence:
  enabled: true
  default:                         # Fallback for any framework not listed below
    backend: s3
    s3:
      bucket: shared-evidence
      region: us-east-1
      prefix: manual/
  frameworks:
    soc2:
      backend: s3
      s3: { bucket: soc2-evidence, region: us-east-1 }
    iso27001:
      backend: azure_blob
      azure_blob: { account: iso27001ev, container: evidence }

# SigComply Cloud (auto-enabled when OIDC is available in CI)
cloud:
  enabled: false
```

### Minimal Example

```yaml
framework: soc2
```

Everything else uses sensible defaults.

---

## Environment Variables

### SigComply Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGCOMPLY_FRAMEWORK` | `soc2` | Compliance framework |
| `SIGCOMPLY_POLICIES` | — | Comma-separated policy names to run (e.g., `cc6_1_mfa,cc6_1_github_mfa`) |
| `SIGCOMPLY_CONTROLS` | — | Comma-separated control IDs to run (e.g., `CC6.1,CC7.1`) |
| `SIGCOMPLY_OUTPUT_FORMAT` | `text` | Output format: text, json, junit |
| `SIGCOMPLY_VERBOSE` | `false` | Set to `true` for verbose output |
| `SIGCOMPLY_FAIL_ON_VIOLATION` | `true` | Set to `false` to always exit 0 |

### Provider Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGCOMPLY_AWS_REGION` | Auto-detect | AWS region (single region) |
| `SIGCOMPLY_GCP_PROJECT` | — | GCP project ID (used by the GCP collector) |
| `SIGCOMPLY_GITHUB_ORG` | — | GitHub organization to collect from |

### Storage Settings

The `storage` block configures the **automated evidence vault**. Manual
evidence has its own per-framework configuration under `manual_evidence`
(see below).

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGCOMPLY_STORAGE_ENABLED` | `false` | Set to `true` to enable evidence storage |
| `SIGCOMPLY_STORAGE_BACKEND` | `local` | Storage backend: `local`, `s3`, `gcs`, `azure_blob` |
| `SIGCOMPLY_STORAGE_PATH` | `./.sigcomply/evidence` | Local storage directory |
| `SIGCOMPLY_STORAGE_BUCKET` | — | Bucket / container name (S3, GCS) |
| `SIGCOMPLY_STORAGE_REGION` | — | AWS region (S3 only) |
| `SIGCOMPLY_STORAGE_PREFIX` | — | Object name prefix |
| `SIGCOMPLY_STORAGE_S3_ENDPOINT` | — | Custom S3 endpoint URL for on-prem (MinIO, Ceph, ECS) |
| `SIGCOMPLY_STORAGE_S3_FORCE_PATH_STYLE` | `false` | Use path-style addressing (required by most on-prem stores) |
| `SIGCOMPLY_STORAGE_S3_AUTH_MODE` | `ambient` | `ambient` or `oidc` |
| `SIGCOMPLY_STORAGE_S3_AUTH_ROLE_ARN` | — | IAM role to assume via STS AssumeRoleWithWebIdentity (when `oidc`) |
| `SIGCOMPLY_STORAGE_S3_AUTH_AUDIENCE` | `sts.amazonaws.com` | Audience claim sent to STS (override for sovereign clouds) |
| `SIGCOMPLY_STORAGE_S3_AUTH_SESSION_NAME` | `sigcomply-cli` | STS session name used in CloudTrail / IAM logs |
| `SIGCOMPLY_STORAGE_GCS_PROJECT_ID` | — | GCP project ID (optional) |
| `SIGCOMPLY_STORAGE_GCS_AUTH_MODE` | `ambient` | `ambient` or `oidc` |
| `SIGCOMPLY_STORAGE_GCS_AUTH_AUDIENCE` | provider default | Audience claim sent to the WIF provider |
| `SIGCOMPLY_STORAGE_GCS_AUTH_WORKLOAD_IDENTITY_PROVIDER` | — | Full WIF provider resource name |
| `SIGCOMPLY_STORAGE_GCS_AUTH_SERVICE_ACCOUNT` | — | Service account email to impersonate |
| `SIGCOMPLY_STORAGE_AZURE_ACCOUNT` | — | Azure storage account name |
| `SIGCOMPLY_STORAGE_AZURE_CONTAINER` | — | Azure blob container |
| `SIGCOMPLY_STORAGE_AZURE_ENDPOINT` | `https://{account}.blob.core.windows.net` | Custom blob endpoint (sovereign clouds, Azurite) |
| `SIGCOMPLY_STORAGE_AZURE_AUTH_MODE` | `ambient` | `ambient` or `oidc` |
| `SIGCOMPLY_STORAGE_AZURE_AUTH_AUDIENCE` | `api://AzureADTokenExchange` | Audience claim for the federated client assertion |
| `SIGCOMPLY_STORAGE_AZURE_AUTH_TENANT_ID` | — | Azure AD tenant ID (when `oidc`) |
| `SIGCOMPLY_STORAGE_AZURE_AUTH_CLIENT_ID` | — | Azure AD app registration client ID (when `oidc`) |

### Manual Evidence Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGCOMPLY_MANUAL_EVIDENCE_ENABLED` | `false` | Set to `true` to enable manual evidence collection |

Per-framework backend selection lives in the YAML file under
`manual_evidence.frameworks.<framework>`. Env vars only toggle the
feature on/off.

### Provider Credentials (Not SigComply-Specific)

| Variable | Provider | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS | Static access key |
| `AWS_SECRET_ACCESS_KEY` | AWS | Static secret key |
| `AWS_SESSION_TOKEN` | AWS | Temporary session token |
| `AWS_PROFILE` | AWS | Named profile from `~/.aws/credentials` |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | AWS | Default region (used by SDK auto-detect) |
| `GITHUB_TOKEN` | GitHub | Personal access token or app token |

---

## Storage Backends

The CLI supports four backend types. The same shape is used for both the
main `storage` block (automated evidence vault) and the per-framework
`manual_evidence` blocks.

### `local` — filesystem

```yaml
backend: local
local:
  path: ./.sigcomply/evidence
```

### `s3` — AWS S3 (and on-prem S3-compatible)

```yaml
backend: s3
s3:
  bucket: my-evidence
  region: us-east-1
  prefix: sigcomply/

  # On-prem (MinIO, Ceph, Dell ECS, NetApp StorageGRID) — optional:
  endpoint: https://minio.internal.corp:9000
  force_path_style: true

  # Auth — defaults to ambient (env vars / IAM role / instance metadata):
  auth:
    mode: oidc                          # ambient | oidc
    role_arn: arn:aws:iam::123:role/sigcomply-evidence
    audience: sts.amazonaws.com         # default; override for sovereign clouds
```

In `oidc` mode the CLI exchanges its CI OIDC token (GitHub Actions /
GitLab CI) for AWS credentials via STS `AssumeRoleWithWebIdentity`.

### `gcs` — Google Cloud Storage

```yaml
backend: gcs
gcs:
  bucket: my-evidence
  prefix: sigcomply/
  project_id: my-gcp-project          # optional

  auth:
    mode: oidc                        # ambient | oidc
    workload_identity_provider: projects/123/locations/global/workloadIdentityPools/sigcomply/providers/github
    service_account: sigcomply@my-gcp-project.iam.gserviceaccount.com
```

In `oidc` mode the CLI exchanges its CI OIDC token via Workload
Identity Federation, then impersonates the configured service account.

### `azure_blob` — Azure Blob Storage

```yaml
backend: azure_blob
azure_blob:
  account: acmeevidence
  container: sigcomply
  prefix: ""
  endpoint: ""                        # optional; defaults to https://{account}.blob.core.windows.net

  auth:
    mode: oidc                        # ambient | oidc
    tenant_id: 00000000-0000-0000-0000-000000000000
    client_id: 11111111-1111-1111-1111-111111111111
    audience: api://AzureADTokenExchange    # default
```

In `oidc` mode the CLI presents its CI OIDC token to Azure AD as a
federated client assertion via `ClientAssertionCredential`.

### Auth modes summary

| Mode | What it does |
|------|--------------|
| `ambient` (default) | Lets the SDK discover credentials: env vars, IAM roles, GCP ADC, Azure DefaultAzureCredential chain. Works seamlessly with `aws-actions/configure-aws-credentials`, `google-github-actions/auth`, `azure/login` action wrappers. |
| `oidc` | The CLI fetches its CI OIDC token (GitHub Actions or GitLab CI) and exchanges it directly with the cloud provider — no separate "configure credentials" action needed in the workflow. |

---

## Manual Evidence Sources

Manual evidence — the user-supplied PDFs that prove non-automatable
controls (signed NDAs, training certs, access reviews, …) — has its
own backend selection per framework. A typical setup keeps SOC 2
evidence in one bucket and ISO 27001 evidence in another, possibly on
a different cloud.

```yaml
manual_evidence:
  enabled: true

  # Fallback for any framework not listed below.
  default:
    backend: s3
    s3:
      bucket: shared-manual-evidence
      region: us-east-1
      prefix: manual/

  # Per-framework overrides.
  frameworks:
    soc2:
      backend: s3
      s3:
        bucket: soc2-manual-evidence
        region: us-east-1
        prefix: ""
    iso27001:
      backend: gcs
      gcs:
        bucket: iso27001-manual-evidence
        prefix: manual/
        auth:
          mode: oidc
          workload_identity_provider: projects/123/locations/global/workloadIdentityPools/sigcomply/providers/github
          service_account: iso27001-evidence@my-project.iam.gserviceaccount.com
```

Resolution at run time for framework `F`:
`frameworks[F]` → `default` → validation error.

### Path layout per evidence ID

For each `evidence_id` in the framework catalog, the CLI looks for
`evidence.pdf` at:

```
{framework}/{evidence_id}/{period}/evidence.pdf
```

(under whatever `prefix` is configured for the framework's backend).
Where `{period}` matches the entry's frequency:

| Frequency | `{period}` example |
|-----------|--------------------|
| daily | `2026-01-15` |
| weekly | `2026-W03` |
| monthly | `2026-01` |
| quarterly | `2026-Q1` |
| yearly | `2026` |

A catalog entry can override this layout with `path_template` and
`filename` — see [Adding a new manual evidence policy](claude/recipes.md).

### Where do I upload?

When evidence is missing, the CLI surfaces the exact upload URI in
the violation message (e.g.
`s3://soc2-manual-evidence/quarterly_access_review/2026-Q1/evidence.pdf`).
You can also query it directly:

```bash
sigcomply evidence path quarterly_access_review
```

---

## CLI Flags

Flags have the highest precedence and override both config file and env vars.

```
sigcomply check [flags]

Flags:
  -f, --framework string      Compliance framework (soc2, iso27001)
      --policies string       Comma-separated policy names to run (e.g., cc6_1_mfa,cc6_1_github_mfa)
      --controls string       Comma-separated control IDs to run (e.g., CC6.1,CC7.1)
  -o, --output string         Output format (text, json, junit)
  -v, --verbose               Verbose output
      --region string         AWS region
      --github-org string     GitHub organization (requires GITHUB_TOKEN)
      --config string         Path to config file (default: .sigcomply.yaml)
      --store                 Store evidence to configured storage
      --storage-path string   Local storage path
      --storage-backend string Storage backend (local, s3, gcs, azure_blob)
      --cloud                 Force cloud submission (requires OIDC in CI)
      --no-cloud              Disable cloud submission
```

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
          SIGCOMPLY_GITHUB_ORG: my-org
        run: sigcomply check --output junit
        # OIDC token is auto-detected from GitHub Actions environment
```

### GitLab CI

```yaml
compliance:
  image: golang:1.24
  variables:
    SIGCOMPLY_FRAMEWORK: soc2
    SIGCOMPLY_GITHUB_ORG: my-org
    SIGCOMPLY_OUTPUT_FORMAT: junit
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

Non-secrets can go in the workflow file or `.sigcomply.yaml`:

| Setting | Where to Set |
|---------|-------------|
| `SIGCOMPLY_FRAMEWORK` | Workflow file, env var, or config file |
| `SIGCOMPLY_GITHUB_ORG` | Workflow file, env var, or config file |
| `SIGCOMPLY_AWS_REGION` | Workflow file, env var, or config file |

---

## Precedence Examples

```bash
# Config file says iso27001, env says soc2, flag says iso27001
# Result: iso27001 (flag wins)
SIGCOMPLY_FRAMEWORK=soc2 sigcomply check --framework iso27001

# Config file says iso27001, env says soc2, no flag
# Result: soc2 (env wins over file)
SIGCOMPLY_FRAMEWORK=soc2 sigcomply check

# Config file says iso27001, no env, no flag
# Result: iso27001 (file wins over default)
sigcomply check

# No config file, no env, no flag
# Result: soc2 (built-in default)
sigcomply check
```
