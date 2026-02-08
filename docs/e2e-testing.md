# E2E Testing Guide

This guide explains how to set up and run end-to-end (E2E) tests for sigcomply-cli against real cloud infrastructure.

## Overview

E2E tests verify the complete compliance workflow:

```
Collect Evidence → Evaluate Policies → Sign/Hash → Store Evidence
```

Unlike unit tests (which use mocks) and integration tests (which use LocalStack), E2E tests run against **real cloud infrastructure** to validate the full system behavior.

### Quick Start: GitHub E2E (No Setup Required)

For a quick E2E test without cloud infrastructure setup, use GitHub testing:

```bash
# Run from GitHub Actions UI or:
gh workflow run e2e.yml -f github_enabled=true -f aws_enabled=false
```

This tests the complete flow using only GitHub repositories - no AWS account needed.

---

## Prerequisites

**For GitHub E2E Tests:**
- GitHub repository with Actions enabled (that's it!)

**For AWS E2E Tests:**
- AWS account dedicated to E2E testing (sandbox)
- AWS CLI configured locally (for setup)

---

## Part 1: AWS Account Setup

### 1.1 Create OIDC Identity Provider

Create an OIDC identity provider to allow GitHub Actions to assume IAM roles without static credentials:

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

### 1.2 Create IAM Role

Create an IAM role that GitHub Actions can assume. Replace `YOUR_ORG` and `ACCOUNT_ID` with your values.

**Trust Policy** (save as `trust-policy.json`):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/sigcomply-cli:*"
        }
      }
    }
  ]
}
```

**Permission Policy** (save as `permission-policy.json`):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadForCompliance",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:GetUser",
        "iam:ListAccessKeys",
        "iam:GetLoginProfile",
        "iam:ListRoles",
        "iam:GetRole"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3ReadForCompliance",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailReadForCompliance",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSForIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Sid": "S3WriteForEvidenceStorage",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::sigcomply-e2e-evidence-ACCOUNT_ID",
        "arn:aws:s3:::sigcomply-e2e-evidence-ACCOUNT_ID/*"
      ]
    }
  ]
}
```

Create the role:
```bash
aws iam create-role \
  --role-name sigcomply-e2e-role \
  --assume-role-policy-document file://trust-policy.json

aws iam put-role-policy \
  --role-name sigcomply-e2e-role \
  --policy-name sigcomply-e2e-policy \
  --policy-document file://permission-policy.json
```

### 1.3 Create Evidence Storage Bucket

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create bucket
aws s3api create-bucket \
  --bucket sigcomply-e2e-evidence-${ACCOUNT_ID} \
  --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket sigcomply-e2e-evidence-${ACCOUNT_ID} \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket sigcomply-e2e-evidence-${ACCOUNT_ID} \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Optional: Lifecycle rule to clean up old tests
aws s3api put-bucket-lifecycle-configuration \
  --bucket sigcomply-e2e-evidence-${ACCOUNT_ID} \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "DeleteOldE2ETests",
      "Status": "Enabled",
      "Filter": {"Prefix": "e2e-tests/"},
      "Expiration": {"Days": 30}
    }]
  }'
```

### 1.4 Create Test Resources

Create predictable resources to verify policy detection:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# ============================================
# IAM Users for MFA Policy Testing
# ============================================

# User WITHOUT MFA (should FAIL CC6.1)
aws iam create-user --user-name sigcomply-e2e-no-mfa
aws iam tag-user --user-name sigcomply-e2e-no-mfa \
  --tags Key=Purpose,Value=E2E-Testing

# ============================================
# S3 Buckets for Encryption Policy Testing
# ============================================

# Bucket WITHOUT encryption (should FAIL CC6.2)
aws s3api create-bucket \
  --bucket sigcomply-e2e-unencrypted-${ACCOUNT_ID} \
  --region us-east-1

# Bucket WITH encryption (should PASS CC6.2)
aws s3api create-bucket \
  --bucket sigcomply-e2e-encrypted-${ACCOUNT_ID} \
  --region us-east-1

aws s3api put-bucket-encryption \
  --bucket sigcomply-e2e-encrypted-${ACCOUNT_ID} \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
    }]
  }'

# ============================================
# CloudTrail for Logging Policy Testing
# ============================================

# Create trail (should PASS CC7.1)
aws cloudtrail create-trail \
  --name sigcomply-e2e-trail \
  --s3-bucket-name sigcomply-e2e-evidence-${ACCOUNT_ID} \
  --s3-key-prefix cloudtrail-logs \
  --is-multi-region-trail \
  --include-global-service-events

aws cloudtrail start-logging --name sigcomply-e2e-trail
```

---

## Part 2: GitHub Repository Configuration

### 2.1 Add Repository Secrets

Go to **Settings → Secrets and variables → Actions** and add:

| Secret | Description | Example |
|--------|-------------|---------|
| `AWS_E2E_ROLE_ARN` | IAM role ARN for OIDC | `arn:aws:iam::123456789012:role/sigcomply-e2e-role` |
| `AWS_E2E_REGION` | AWS region | `us-east-1` |
| `AWS_E2E_EVIDENCE_BUCKET` | S3 bucket for evidence | `sigcomply-e2e-evidence-123456789012` |

### 2.2 Add Repository Variables (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `E2E_STORAGE_PREFIX` | S3 prefix for test runs | `e2e-tests` |

---

## Part 3: Running E2E Tests

### Via GitHub Actions (Recommended)

Trigger the E2E workflow manually:

```bash
# Using GitHub CLI
gh workflow run e2e.yml \
  -f aws_enabled=true \
  -f framework=soc2 \
  -f storage_enabled=true \
  -f storage_backend=s3 \
  -f verbose=true

# Check status
gh run list --workflow=e2e.yml
gh run view <run-id>
```

Or use the GitHub UI:
1. Go to **Actions** tab
2. Select **E2E Tests** workflow
3. Click **Run workflow**
4. Configure inputs and run

### Via Command Line (Local)

Run E2E tests locally with AWS credentials:

```bash
# Set environment variables
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export AWS_REGION=us-east-1
export SIGCOMPLY_STORAGE_BUCKET=sigcomply-e2e-evidence-123456789012
export SIGCOMPLY_STORAGE_REGION=us-east-1

# Run E2E tests
make test-e2e

# Or run specific tests
go test -tags=e2e -v ./test/e2e/... -run TestAWS_Connectivity
```

---

## Part 4: Workflow Inputs

The E2E workflow supports these configuration inputs:

### Data Sources

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `aws_enabled` | boolean | `true` | Enable AWS data collection |
| `github_enabled` | boolean | `false` | Enable GitHub data collection |
| `github_org` | string | `""` | GitHub organization (if enabled) |

### Compliance

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `framework` | choice | `soc2` | Compliance framework (soc2, hipaa, iso27001) |

### Storage

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `storage_enabled` | boolean | `true` | Store evidence to S3 |
| `storage_backend` | choice | `s3` | Storage backend (s3, local) |

### Output

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `verbose` | boolean | `false` | Enable verbose output |
| `cloud_submit` | boolean | `false` | Submit results to SigComply Cloud |

---

## Part 5: What Gets Tested

The E2E tests verify:

1. **AWS Connectivity** - Can connect to AWS with OIDC credentials
2. **Evidence Collection** - Collects IAM users, S3 buckets, CloudTrail trails
3. **Policy Evaluation** - SOC2 policies evaluate correctly against real resources
4. **Evidence Hashing** - SHA-256 hashes are computed for all evidence
5. **S3 Storage** - Evidence and manifests are stored correctly
6. **Expected Violations** - Test resources trigger expected policy violations

---

## Part 6: Cleanup

To remove E2E test resources:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Delete test users
aws iam delete-user --user-name sigcomply-e2e-no-mfa

# Delete test buckets (must be empty first)
aws s3 rb s3://sigcomply-e2e-unencrypted-${ACCOUNT_ID} --force
aws s3 rb s3://sigcomply-e2e-encrypted-${ACCOUNT_ID} --force

# Stop and delete CloudTrail
aws cloudtrail stop-logging --name sigcomply-e2e-trail
aws cloudtrail delete-trail --name sigcomply-e2e-trail

# Delete evidence bucket (contains test data)
aws s3 rb s3://sigcomply-e2e-evidence-${ACCOUNT_ID} --force

# Delete IAM role
aws iam delete-role-policy --role-name sigcomply-e2e-role --policy-name sigcomply-e2e-policy
aws iam delete-role --role-name sigcomply-e2e-role

# Delete OIDC provider
aws iam delete-open-id-connect-provider \
  --open-id-connect-provider-arn arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com
```

---

## Troubleshooting

### OIDC Authentication Fails

```
Error: Could not assume role with OIDC
```

Check:
1. OIDC provider thumbprint is correct
2. Trust policy has correct repository name
3. Repository secrets are set correctly

### No Resources Evaluated

```
WARNING: No resources evaluated - check AWS permissions
```

Check:
1. IAM role has required permissions
2. Region is set correctly
3. Resources exist in the account

### S3 Storage Fails

```
Error: Access Denied
```

Check:
1. IAM role has S3 write permissions for the bucket
2. Bucket exists and is in the correct region
3. Bucket name matches the secret value

---

## GitHub E2E Testing (No Cloud Setup Required)

GitHub E2E tests can run without any cloud infrastructure setup. They use GitHub's built-in `GITHUB_TOKEN` and local storage.

### What Gets Tested

1. **GitHub Connectivity** - Can authenticate with GitHub token
2. **Repository Collection** - Collects repos with branch protection settings
3. **Member Collection** - Collects org members (requires org membership)
4. **Policy Evaluation** - Evaluates GitHub-specific SOC2 policies:
   - `cc6_1_github_mfa` - Member 2FA requirement
   - `cc8_1_branch_protection` - Repository branch protection
5. **Evidence Hashing** - SHA-256 hashes for all evidence

### Running GitHub E2E Tests

#### Via GitHub Actions (Recommended)

Trigger the E2E workflow with GitHub enabled:

```bash
gh workflow run e2e.yml \
  -f github_enabled=true \
  -f aws_enabled=false \
  -f framework=soc2 \
  -f verbose=true

# Check status
gh run list --workflow=e2e.yml
```

Or use the GitHub UI:
1. Go to **Actions** tab
2. Select **E2E Tests** workflow
3. Click **Run workflow**
4. Enable "GitHub data collection", disable "AWS data collection"
5. Run the workflow

#### Via Command Line (Local)

Run GitHub E2E tests locally:

```bash
# Set your GitHub token
export GITHUB_TOKEN=ghp_your_token_here

# Optional: specify organization
export E2E_GITHUB_ORG=your-org-name

# Run GitHub E2E tests
go test -tags=e2e -v ./test/e2e/... -run TestGitHub
```

### GitHub Token Permissions

The `GITHUB_TOKEN` needs these permissions:
- `repo` - Read access to repositories
- `read:org` - Read access to organization (for member collection)

In GitHub Actions, the default `GITHUB_TOKEN` has sufficient permissions for the current repository.

### Notes on Member 2FA Testing

To check organization member 2FA status:
- You must be an **organization admin**
- The token must have `admin:org` scope
- Without admin access, 2FA status will be "unknown"

---

## Extending E2E Tests

### Adding New Cloud Providers

The workflow is designed for extensibility. To add GCP support:

1. Add workflow inputs:
   ```yaml
   gcp_enabled:
     type: boolean
     default: false
   ```

2. Add a new job:
   ```yaml
   e2e-gcp:
     if: ${{ inputs.gcp_enabled }}
     steps:
       - uses: google-github-actions/auth@v2
         with:
           workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY }}
   ```

3. Create GCP test files in `test/e2e/gcp_test.go`

### Adding New Data Sources

To add new data sources (Workday, Okta, etc.):

1. Add workflow inputs for the new source
2. Add environment variables for authentication
3. Update the CLI to support the new collector
4. Create E2E tests in `test/e2e/`
