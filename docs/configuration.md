# Configuration Guide

SigComply CLI can be configured through three sources, listed from lowest to highest priority:

1. **Config file** (`.sigcomply.yaml`)
2. **Environment variables** (`SIGCOMPLY_*` and provider-specific)
3. **CLI flags** (`--framework`, `--region`, etc.)

Higher-priority sources override lower ones. For example, `--framework iso27001` beats
`SIGCOMPLY_FRAMEWORK=soc2` which beats `framework: hipaa` in the config file.

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
framework: soc2                    # Options: soc2, iso27001, hipaa

# AWS settings (credentials come from environment / IAM, not here)
aws:
  regions:
    - us-east-1
    - eu-west-1

# GitHub settings (token comes from GITHUB_TOKEN env var, not here)
github:
  org: my-org

# Output settings
output:
  format: text                     # Options: text, json, sarif, junit
  verbose: false

# CI/CD behavior
ci:
  fail_on_violation: true          # Exit code 1 on violations
  fail_severity: low               # Minimum severity to fail: low, medium, high, critical

# Evidence storage
storage:
  enabled: false
  backend: local                   # Options: local, s3
  local:
    path: ./.sigcomply/evidence
  s3:
    bucket: my-bucket
    region: us-east-1
    prefix: compliance/

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
| `SIGCOMPLY_OUTPUT_FORMAT` | `text` | Output format: text, json, sarif, junit |
| `SIGCOMPLY_VERBOSE` | `false` | Set to `true` for verbose output |
| `SIGCOMPLY_FAIL_ON_VIOLATION` | `true` | Set to `false` to always exit 0 |

### Provider Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGCOMPLY_AWS_REGION` | Auto-detect | AWS region (single region) |
| `SIGCOMPLY_GITHUB_ORG` | — | GitHub organization to collect from |

### Storage Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGCOMPLY_STORAGE_ENABLED` | `false` | Set to `true` to enable evidence storage |
| `SIGCOMPLY_STORAGE_BACKEND` | `local` | Storage backend: `local`, `s3` |
| `SIGCOMPLY_STORAGE_PATH` | `./.sigcomply/evidence` | Local storage directory |
| `SIGCOMPLY_STORAGE_BUCKET` | — | S3 bucket name |
| `SIGCOMPLY_STORAGE_REGION` | — | S3 bucket region |
| `SIGCOMPLY_STORAGE_PREFIX` | — | S3 key prefix |

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

## CLI Flags

Flags have the highest precedence and override both config file and env vars.

```
sigcomply check [flags]

Flags:
  -f, --framework string      Compliance framework (soc2, hipaa, iso27001)
  -o, --output string         Output format (text, json, junit)
  -v, --verbose               Verbose output
      --region string         AWS region
      --github-org string     GitHub organization (requires GITHUB_TOKEN)
      --config string         Path to config file (default: .sigcomply.yaml)
      --store                 Store evidence to configured storage
      --storage-path string   Local storage path
      --storage-backend string Storage backend (local, s3)
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
# Config file says iso27001, env says hipaa, flag says soc2
# Result: soc2 (flag wins)
SIGCOMPLY_FRAMEWORK=hipaa sigcomply check --framework soc2

# Config file says iso27001, env says hipaa, no flag
# Result: hipaa (env wins over file)
SIGCOMPLY_FRAMEWORK=hipaa sigcomply check

# Config file says iso27001, no env, no flag
# Result: iso27001 (file wins over default)
sigcomply check

# No config file, no env, no flag
# Result: soc2 (built-in default)
sigcomply check
```
