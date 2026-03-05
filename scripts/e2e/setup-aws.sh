#!/usr/bin/env bash
# SigComply E2E AWS Environment Setup
#
# Provisions all AWS resources needed for E2E testing.
# Idempotent - safe to re-run.
#
# Usage:
#   ./scripts/e2e/setup-aws.sh

set -euo pipefail

# Colors for output (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Configuration
EXPECTED_ACCOUNT_ID="552644938807"
REGION="us-east-1"

# IAM
IAM_USERS=(
    "sigcomply-e2e-positive"
    "sigcomply-e2e-negative"
    "sigcomply-e2e-console-mfa"
    "sigcomply-e2e-console-nomfa"
)
POSITIVE_POLICY_NAME="sigcomply-e2e-positive-policy"
NEGATIVE_POLICY_NAME="sigcomply-e2e-negative-policy"

# Resources
S3_BUCKET="sigcomply-e2e-tests"
CLOUDTRAIL_NAME="sigcomply-e2e-trail"
CLOUDTRAIL_BUCKET="sigcomply-e2e-cloudtrail-logs"
LOG_GROUP_NAME="sigcomply-e2e-test-logs"
KMS_ALIAS="alias/sigcomply-e2e-test"
ECR_REPO="sigcomply-e2e-test"
RDS_INSTANCE="sigcomply-e2e-test"
RDS_MASTER_USER="admin"
RDS_MASTER_PASS="e2etestpass123"
DYNAMODB_TABLE="sigcomply-e2e-test"
LAMBDA_FUNCTION="sigcomply-e2e-test"
LAMBDA_ROLE="sigcomply-e2e-lambda-role"
SECRET_NAME="sigcomply-e2e-test-secret"

# Helper functions
info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
    exit 1
}

# Check if a command exists
require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        error "Required command not found: $1"
    fi
}

# Validate prerequisites
validate_prerequisites() {
    info "Validating prerequisites..."

    require_cmd aws
    require_cmd jq

    # Check AWS authentication
    local account_id
    account_id=$(aws sts get-caller-identity --query "Account" --output text 2>/dev/null) || \
        error "AWS CLI is not authenticated. Run 'aws configure' or set AWS credentials."

    if [ "$account_id" != "$EXPECTED_ACCOUNT_ID" ]; then
        error "Wrong AWS account. Expected $EXPECTED_ACCOUNT_ID, got $account_id"
    fi

    success "AWS CLI authenticated to account $account_id"
}

# Check if IAM user exists
iam_user_exists() {
    aws iam get-user --user-name "$1" >/dev/null 2>&1
}

# Create IAM users
create_iam_users() {
    info "Creating/verifying IAM users..."

    for user in "${IAM_USERS[@]}"; do
        if iam_user_exists "$user"; then
            success "IAM user already exists: $user"
        else
            aws iam create-user --user-name "$user" >/dev/null
            success "Created IAM user: $user"
        fi
    done

    # Create console access for console users
    for user in "sigcomply-e2e-console-mfa" "sigcomply-e2e-console-nomfa"; do
        if aws iam get-login-profile --user-name "$user" >/dev/null 2>&1; then
            success "Login profile already exists: $user"
        else
            aws iam create-login-profile \
                --user-name "$user" \
                --password "E2eTest!Console123" \
                --no-password-reset-required >/dev/null
            success "Created login profile: $user"
        fi
    done

    # Create virtual MFA device for console-mfa user (if not exists)
    local mfa_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:mfa/sigcomply-e2e-console-mfa"
    if aws iam list-mfa-devices --user-name "sigcomply-e2e-console-mfa" --query "MFADevices[0]" --output text 2>/dev/null | grep -q "arn:"; then
        success "MFA device already attached: sigcomply-e2e-console-mfa"
    else
        warn "MFA device for sigcomply-e2e-console-mfa must be configured manually"
    fi
}

# Create IAM policies
create_iam_policies() {
    info "Creating/updating IAM policies..."

    # Positive policy: full read access for all collectors + S3 storage
    local positive_policy
    positive_policy=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "IAMReadAccess",
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:GetUser",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:ListUserPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:GetLoginProfile",
                "iam:ListGroupsForUser",
                "iam:GetAccountAuthorizationDetails",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport"
            ],
            "Resource": "*"
        },
        {
            "Sid": "S3ReadAccess",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketAcl",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetAccountPublicAccessBlock",
                "s3:GetBucketTagging",
                "s3:ListBucket"
            ],
            "Resource": "*"
        },
        {
            "Sid": "S3EvidenceStorage",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::sigcomply-e2e-tests",
                "arn:aws:s3:::sigcomply-e2e-tests/*"
            ]
        },
        {
            "Sid": "CloudTrailReadAccess",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudWatchLogsReadAccess",
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:GetLogEvents",
                "logs:DescribeMetricFilters"
            ],
            "Resource": "*"
        },
        {
            "Sid": "KMSReadAccess",
            "Effect": "Allow",
            "Action": [
                "kms:ListKeys",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:GetKeyRotationStatus",
                "kms:ListAliases"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ECRReadAccess",
            "Effect": "Allow",
            "Action": [
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeImages",
                "ecr:ListImages",
                "ecr:GetLifecyclePolicy",
                "ecr:DescribeImageScanFindings"
            ],
            "Resource": "*"
        },
        {
            "Sid": "RDSReadAccess",
            "Effect": "Allow",
            "Action": [
                "rds:DescribeDBInstances",
                "rds:DescribeDBClusters",
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBSubnetGroups",
                "rds:ListTagsForResource",
                "rds:DescribeEventSubscriptions"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SecurityHubReadAccess",
            "Effect": "Allow",
            "Action": [
                "securityhub:DescribeHub",
                "securityhub:GetFindings"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudWatchAlarmsReadAccess",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:DescribeAlarms"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SecretsManagerReadAccess",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:ListSecrets",
                "secretsmanager:DescribeSecret"
            ],
            "Resource": "*"
        },
        {
            "Sid": "LambdaReadAccess",
            "Effect": "Allow",
            "Action": [
                "lambda:ListFunctions",
                "lambda:GetPolicy",
                "lambda:GetFunction"
            ],
            "Resource": "*"
        },
        {
            "Sid": "S3ControlReadAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetAccountPublicAccessBlock"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DynamoDBReadAccess",
            "Effect": "Allow",
            "Action": [
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                "dynamodb:DescribeContinuousBackups"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ECSReadAccess",
            "Effect": "Allow",
            "Action": [
                "ecs:ListClusters",
                "ecs:DescribeClusters"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EKSReadAccess",
            "Effect": "Allow",
            "Action": [
                "eks:ListClusters",
                "eks:DescribeCluster"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ACMReadAccess",
            "Effect": "Allow",
            "Action": [
                "acm:ListCertificates",
                "acm:DescribeCertificate"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudFrontReadAccess",
            "Effect": "Allow",
            "Action": [
                "cloudfront:ListDistributions",
                "cloudfront:GetDistribution"
            ],
            "Resource": "*"
        },
        {
            "Sid": "WAFReadAccess",
            "Effect": "Allow",
            "Action": [
                "wafv2:ListWebACLs",
                "wafv2:ListResourcesForWebACL",
                "wafv2:GetWebACL"
            ],
            "Resource": "*"
        },
        {
            "Sid": "MacieReadAccess",
            "Effect": "Allow",
            "Action": [
                "macie2:GetMacieSession"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SSMReadAccess",
            "Effect": "Allow",
            "Action": [
                "ssm:DescribeInstanceInformation",
                "ssm:GetServiceSetting"
            ],
            "Resource": "*"
        },
        {
            "Sid": "STSAccess",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
)

    # Negative policy: STS-only
    local negative_policy
    negative_policy=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "STSOnly",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
)

    # Create or update positive policy
    local positive_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/${POSITIVE_POLICY_NAME}"
    if aws iam get-policy --policy-arn "$positive_arn" >/dev/null 2>&1; then
        # Policy exists, create new version (delete oldest non-default if at limit)
        local versions
        versions=$(aws iam list-policy-versions --policy-arn "$positive_arn" --query "Versions[?!IsDefaultVersion].VersionId" --output text)
        local version_count
        version_count=$(echo "$versions" | wc -w | tr -d ' ')
        if [ "$version_count" -ge 4 ]; then
            local oldest
            oldest=$(echo "$versions" | awk '{print $NF}')
            aws iam delete-policy-version --policy-arn "$positive_arn" --version-id "$oldest"
        fi
        aws iam create-policy-version \
            --policy-arn "$positive_arn" \
            --policy-document "$positive_policy" \
            --set-as-default >/dev/null
        success "Updated IAM policy: $POSITIVE_POLICY_NAME"
    else
        aws iam create-policy \
            --policy-name "$POSITIVE_POLICY_NAME" \
            --policy-document "$positive_policy" >/dev/null
        success "Created IAM policy: $POSITIVE_POLICY_NAME"
    fi

    # Attach positive policy to positive user
    aws iam attach-user-policy \
        --user-name "sigcomply-e2e-positive" \
        --policy-arn "arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/${POSITIVE_POLICY_NAME}" 2>/dev/null || true
    success "Attached $POSITIVE_POLICY_NAME to sigcomply-e2e-positive"

    # Create or update negative policy
    local negative_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/${NEGATIVE_POLICY_NAME}"
    if aws iam get-policy --policy-arn "$negative_arn" >/dev/null 2>&1; then
        local versions
        versions=$(aws iam list-policy-versions --policy-arn "$negative_arn" --query "Versions[?!IsDefaultVersion].VersionId" --output text)
        local version_count
        version_count=$(echo "$versions" | wc -w | tr -d ' ')
        if [ "$version_count" -ge 4 ]; then
            local oldest
            oldest=$(echo "$versions" | awk '{print $NF}')
            aws iam delete-policy-version --policy-arn "$negative_arn" --version-id "$oldest"
        fi
        aws iam create-policy-version \
            --policy-arn "$negative_arn" \
            --policy-document "$negative_policy" \
            --set-as-default >/dev/null
        success "Updated IAM policy: $NEGATIVE_POLICY_NAME"
    else
        aws iam create-policy \
            --policy-name "$NEGATIVE_POLICY_NAME" \
            --policy-document "$negative_policy" >/dev/null
        success "Created IAM policy: $NEGATIVE_POLICY_NAME"
    fi

    # Attach negative policy to negative user
    aws iam attach-user-policy \
        --user-name "sigcomply-e2e-negative" \
        --policy-arn "arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/${NEGATIVE_POLICY_NAME}" 2>/dev/null || true
    success "Attached $NEGATIVE_POLICY_NAME to sigcomply-e2e-negative"
}

# Create access keys for programmatic users
create_access_keys() {
    info "Creating access keys for programmatic users..."

    local positive_key=""
    local positive_secret=""
    local negative_key=""
    local negative_secret=""

    # Positive user
    local existing_keys
    existing_keys=$(aws iam list-access-keys --user-name "sigcomply-e2e-positive" --query "AccessKeyMetadata[].AccessKeyId" --output text)
    if [ -n "$existing_keys" ] && [ "$existing_keys" != "None" ]; then
        success "Access key already exists for sigcomply-e2e-positive: $existing_keys"
        warn "Cannot retrieve existing secret. If you need it, delete the key and re-run."
    else
        local key_output
        key_output=$(aws iam create-access-key --user-name "sigcomply-e2e-positive" --output json)
        positive_key=$(echo "$key_output" | jq -r '.AccessKey.AccessKeyId')
        positive_secret=$(echo "$key_output" | jq -r '.AccessKey.SecretAccessKey')
        success "Created access key for sigcomply-e2e-positive: $positive_key"
    fi

    # Negative user
    existing_keys=$(aws iam list-access-keys --user-name "sigcomply-e2e-negative" --query "AccessKeyMetadata[].AccessKeyId" --output text)
    if [ -n "$existing_keys" ] && [ "$existing_keys" != "None" ]; then
        success "Access key already exists for sigcomply-e2e-negative: $existing_keys"
        warn "Cannot retrieve existing secret. If you need it, delete the key and re-run."
    else
        local key_output
        key_output=$(aws iam create-access-key --user-name "sigcomply-e2e-negative" --output json)
        negative_key=$(echo "$key_output" | jq -r '.AccessKey.AccessKeyId')
        negative_secret=$(echo "$key_output" | jq -r '.AccessKey.SecretAccessKey')
        success "Created access key for sigcomply-e2e-negative: $negative_key"
    fi

    # Store for summary output
    POSITIVE_ACCESS_KEY_ID="$positive_key"
    POSITIVE_SECRET_ACCESS_KEY="$positive_secret"
    NEGATIVE_ACCESS_KEY_ID="$negative_key"
    NEGATIVE_SECRET_ACCESS_KEY="$negative_secret"
}

# Create S3 bucket
create_s3_bucket() {
    local bucket="$1"
    info "Creating S3 bucket: $bucket..."

    if aws s3api head-bucket --bucket "$bucket" 2>/dev/null; then
        success "S3 bucket already exists: $bucket"
        return
    fi

    # us-east-1 doesn't use LocationConstraint
    if [ "$REGION" = "us-east-1" ]; then
        aws s3api create-bucket --bucket "$bucket" --region "$REGION" >/dev/null
    else
        aws s3api create-bucket --bucket "$bucket" --region "$REGION" \
            --create-bucket-configuration LocationConstraint="$REGION" >/dev/null
    fi
    success "Created S3 bucket: $bucket"
}

# Provision S3 evidence bucket
provision_s3_bucket() {
    create_s3_bucket "$S3_BUCKET"
}

# Provision CloudTrail
provision_cloudtrail() {
    info "Provisioning CloudTrail: $CLOUDTRAIL_NAME..."

    # Create the CloudTrail logs bucket
    create_s3_bucket "$CLOUDTRAIL_BUCKET"

    # Set bucket policy for CloudTrail
    local bucket_policy
    bucket_policy=$(cat <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${CLOUDTRAIL_BUCKET}",
            "Condition": {
                "StringEquals": {
                    "aws:SourceArn": "arn:aws:cloudtrail:${REGION}:${EXPECTED_ACCOUNT_ID}:trail/${CLOUDTRAIL_NAME}"
                }
            }
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${CLOUDTRAIL_BUCKET}/AWSLogs/${EXPECTED_ACCOUNT_ID}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "aws:SourceArn": "arn:aws:cloudtrail:${REGION}:${EXPECTED_ACCOUNT_ID}:trail/${CLOUDTRAIL_NAME}"
                }
            }
        }
    ]
}
POLICY
)

    aws s3api put-bucket-policy --bucket "$CLOUDTRAIL_BUCKET" --policy "$bucket_policy"
    success "Set bucket policy on $CLOUDTRAIL_BUCKET"

    # Create or verify trail
    if aws cloudtrail describe-trails --trail-name-list "$CLOUDTRAIL_NAME" --query "trailList[0].Name" --output text 2>/dev/null | grep -q "$CLOUDTRAIL_NAME"; then
        success "CloudTrail already exists: $CLOUDTRAIL_NAME"
    else
        aws cloudtrail create-trail \
            --name "$CLOUDTRAIL_NAME" \
            --s3-bucket-name "$CLOUDTRAIL_BUCKET" \
            --is-multi-region-trail \
            --enable-log-file-validation >/dev/null
        success "Created CloudTrail: $CLOUDTRAIL_NAME"
    fi

    # Start logging
    aws cloudtrail start-logging --name "$CLOUDTRAIL_NAME" 2>/dev/null || true
    success "CloudTrail logging started: $CLOUDTRAIL_NAME"
}

# Provision CloudWatch log group
provision_cloudwatch() {
    info "Provisioning CloudWatch log group: $LOG_GROUP_NAME..."

    if aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP_NAME" \
        --query "logGroups[?logGroupName=='$LOG_GROUP_NAME'].logGroupName" --output text 2>/dev/null | grep -q "$LOG_GROUP_NAME"; then
        success "CloudWatch log group already exists: $LOG_GROUP_NAME"
    else
        aws logs create-log-group --log-group-name "$LOG_GROUP_NAME" --region "$REGION"
        success "Created CloudWatch log group: $LOG_GROUP_NAME"
    fi
}

# Provision KMS key
provision_kms() {
    info "Provisioning KMS key: $KMS_ALIAS..."

    # Check if alias exists
    local key_id
    key_id=$(aws kms list-aliases --query "Aliases[?AliasName=='$KMS_ALIAS'].TargetKeyId" --output text 2>/dev/null)

    if [ -n "$key_id" ] && [ "$key_id" != "None" ]; then
        success "KMS key already exists: $KMS_ALIAS (key: $key_id)"
    else
        # Create key
        key_id=$(aws kms create-key \
            --description "SigComply E2E test key" \
            --query "KeyMetadata.KeyId" --output text)

        # Create alias
        aws kms create-alias \
            --alias-name "$KMS_ALIAS" \
            --target-key-id "$key_id"

        success "Created KMS key: $KMS_ALIAS (key: $key_id)"
    fi
}

# Provision ECR repository
provision_ecr() {
    info "Provisioning ECR repository: $ECR_REPO..."

    if aws ecr describe-repositories --repository-names "$ECR_REPO" --region "$REGION" >/dev/null 2>&1; then
        success "ECR repository already exists: $ECR_REPO"
    else
        aws ecr create-repository \
            --repository-name "$ECR_REPO" \
            --region "$REGION" \
            --image-scanning-configuration scanOnPush=false >/dev/null
        success "Created ECR repository: $ECR_REPO (scanOnPush=false)"
    fi
}

# Provision RDS instance
provision_rds() {
    info "Provisioning RDS instance: $RDS_INSTANCE..."

    local status
    status=$(aws rds describe-db-instances --db-instance-identifier "$RDS_INSTANCE" \
        --query "DBInstances[0].DBInstanceStatus" --output text 2>/dev/null) || true

    if [ -n "$status" ] && [ "$status" != "None" ]; then
        success "RDS instance already exists: $RDS_INSTANCE (status: $status)"
    else
        aws rds create-db-instance \
            --db-instance-identifier "$RDS_INSTANCE" \
            --db-instance-class db.t3.micro \
            --engine mysql \
            --engine-version "8.0" \
            --master-username "$RDS_MASTER_USER" \
            --master-user-password "$RDS_MASTER_PASS" \
            --allocated-storage 20 \
            --no-storage-encrypted \
            --no-publicly-accessible \
            --backup-retention-period 0 \
            --no-multi-az \
            --region "$REGION" >/dev/null
        success "Created RDS instance: $RDS_INSTANCE (intentionally non-compliant)"
    fi
}

# Wait for RDS to become available
wait_for_rds() {
    local status
    status=$(aws rds describe-db-instances --db-instance-identifier "$RDS_INSTANCE" \
        --query "DBInstances[0].DBInstanceStatus" --output text 2>/dev/null) || true

    if [ "$status" = "available" ]; then
        success "RDS instance is available"
        return
    fi

    if [ -z "$status" ] || [ "$status" = "None" ]; then
        return
    fi

    info "Waiting for RDS instance to become available (status: $status)..."
    info "This can take 5-10 minutes..."

    local elapsed=0
    local timeout=900  # 15 minutes

    while [ $elapsed -lt $timeout ]; do
        status=$(aws rds describe-db-instances --db-instance-identifier "$RDS_INSTANCE" \
            --query "DBInstances[0].DBInstanceStatus" --output text 2>/dev/null) || true

        if [ "$status" = "available" ]; then
            success "RDS instance is now available"
            return
        fi

        printf "."
        sleep 30
        elapsed=$((elapsed + 30))
    done

    echo ""
    warn "RDS instance not yet available after ${timeout}s (status: $status). It will continue provisioning in the background."
}

# Provision DynamoDB table (intentionally non-compliant: default encryption, no PITR)
provision_dynamodb() {
    info "Provisioning DynamoDB table: $DYNAMODB_TABLE..."

    if aws dynamodb describe-table --table-name "$DYNAMODB_TABLE" --region "$REGION" >/dev/null 2>&1; then
        success "DynamoDB table already exists: $DYNAMODB_TABLE"
        return
    fi

    aws dynamodb create-table \
        --table-name "$DYNAMODB_TABLE" \
        --attribute-definitions AttributeName=id,AttributeType=S \
        --key-schema AttributeName=id,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST \
        --region "$REGION" >/dev/null
    success "Created DynamoDB table: $DYNAMODB_TABLE (default encryption, no PITR — intentionally non-compliant)"
}

# Provision Lambda function (intentionally non-compliant: deprecated runtime)
provision_lambda() {
    info "Provisioning Lambda function: $LAMBDA_FUNCTION..."

    if aws lambda get-function --function-name "$LAMBDA_FUNCTION" --region "$REGION" >/dev/null 2>&1; then
        success "Lambda function already exists: $LAMBDA_FUNCTION"
        return
    fi

    # Create execution role if it doesn't exist
    local role_arn
    role_arn=$(aws iam get-role --role-name "$LAMBDA_ROLE" --query "Role.Arn" --output text 2>/dev/null) || true

    if [ -z "$role_arn" ] || [ "$role_arn" = "None" ]; then
        local assume_role_policy
        assume_role_policy=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
)
        role_arn=$(aws iam create-role \
            --role-name "$LAMBDA_ROLE" \
            --assume-role-policy-document "$assume_role_policy" \
            --query "Role.Arn" --output text)
        success "Created Lambda execution role: $LAMBDA_ROLE"

        # Wait for role to propagate
        info "Waiting for IAM role to propagate..."
        sleep 10
    else
        success "Lambda execution role already exists: $LAMBDA_ROLE"
    fi

    # Create minimal zip with a dummy handler
    local zip_file="/tmp/sigcomply-e2e-lambda.zip"
    echo 'def handler(event, context): return {"statusCode": 200}' > /tmp/handler.py
    (cd /tmp && zip -q "$zip_file" handler.py)
    rm -f /tmp/handler.py

    aws lambda create-function \
        --function-name "$LAMBDA_FUNCTION" \
        --runtime python3.8 \
        --handler handler.handler \
        --role "$role_arn" \
        --zip-file "fileb://$zip_file" \
        --region "$REGION" >/dev/null
    rm -f "$zip_file"
    success "Created Lambda function: $LAMBDA_FUNCTION (python3.8 — intentionally non-compliant)"
}

# Provision Secrets Manager secret (intentionally non-compliant: no rotation)
provision_secrets_manager() {
    info "Provisioning Secrets Manager secret: $SECRET_NAME..."

    if aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --region "$REGION" >/dev/null 2>&1; then
        success "Secrets Manager secret already exists: $SECRET_NAME"
        return
    fi

    aws secretsmanager create-secret \
        --name "$SECRET_NAME" \
        --secret-string '{"username":"e2e","password":"test123"}' \
        --region "$REGION" >/dev/null
    success "Created Secrets Manager secret: $SECRET_NAME (no rotation — intentionally non-compliant)"
}

# Print summary
print_summary() {
    echo ""
    echo "  ========================================"
    echo "  SigComply E2E AWS Setup Complete"
    echo "  ========================================"
    echo ""
    echo "  Resources provisioned:"
    echo "    - IAM users: ${IAM_USERS[*]}"
    echo "    - IAM policies: $POSITIVE_POLICY_NAME, $NEGATIVE_POLICY_NAME"
    echo "    - S3 bucket: $S3_BUCKET"
    echo "    - CloudTrail: $CLOUDTRAIL_NAME (bucket: $CLOUDTRAIL_BUCKET)"
    echo "    - CloudWatch log group: $LOG_GROUP_NAME"
    echo "    - KMS key: $KMS_ALIAS"
    echo "    - ECR repo: $ECR_REPO"
    echo "    - RDS instance: $RDS_INSTANCE"
    echo "    - DynamoDB table: $DYNAMODB_TABLE"
    echo "    - Lambda function: $LAMBDA_FUNCTION (role: $LAMBDA_ROLE)"
    echo "    - Secrets Manager secret: $SECRET_NAME"
    echo ""

    if [ -n "${POSITIVE_ACCESS_KEY_ID:-}" ] || [ -n "${NEGATIVE_ACCESS_KEY_ID:-}" ]; then
        echo "  # Add these to your shell or .env file:"
        if [ -n "${POSITIVE_ACCESS_KEY_ID:-}" ]; then
            echo "  export E2E_AWS_ACCESS_KEY_ID=\"$POSITIVE_ACCESS_KEY_ID\""
            echo "  export E2E_AWS_SECRET_ACCESS_KEY=\"$POSITIVE_SECRET_ACCESS_KEY\""
        fi
        echo "  export E2E_AWS_REGION=\"$REGION\""
        if [ -n "${NEGATIVE_ACCESS_KEY_ID:-}" ]; then
            echo "  export E2E_AWS_NEGATIVE_ACCESS_KEY_ID=\"$NEGATIVE_ACCESS_KEY_ID\""
            echo "  export E2E_AWS_NEGATIVE_SECRET_ACCESS_KEY=\"$NEGATIVE_SECRET_ACCESS_KEY\""
        fi
        echo "  export E2E_S3_BUCKET=\"$S3_BUCKET\""
        echo "  export E2E_HMAC_SECRET=\"e2e-test-hmac-secret-default\""
        echo ""
    else
        echo "  No new access keys were created (they already exist)."
        echo "  If you need new keys, delete the existing ones and re-run."
        echo ""
        echo "  Existing environment variables needed:"
        echo "  export E2E_AWS_REGION=\"$REGION\""
        echo "  export E2E_S3_BUCKET=\"$S3_BUCKET\""
        echo "  export E2E_HMAC_SECRET=\"e2e-test-hmac-secret-default\""
        echo ""
    fi
}

# Main
main() {
    echo ""
    echo "  SigComply E2E AWS Setup"
    echo "  ======================="
    echo ""

    validate_prerequisites

    # Initialize key variables
    POSITIVE_ACCESS_KEY_ID=""
    POSITIVE_SECRET_ACCESS_KEY=""
    NEGATIVE_ACCESS_KEY_ID=""
    NEGATIVE_SECRET_ACCESS_KEY=""

    create_iam_users
    create_iam_policies
    create_access_keys
    provision_s3_bucket
    provision_cloudtrail
    provision_cloudwatch
    provision_kms
    provision_ecr
    provision_rds
    wait_for_rds
    provision_dynamodb
    provision_lambda
    provision_secrets_manager
    print_summary
}

main
