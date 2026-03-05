#!/usr/bin/env bash
# SigComply E2E AWS Environment Teardown
#
# Destroys all AWS resources provisioned by setup-aws.sh.
# Does NOT delete IAM users/policies/access keys (they are long-lived).
#
# Usage:
#   ./scripts/e2e/teardown-aws.sh           # Interactive confirmation
#   ./scripts/e2e/teardown-aws.sh --force   # Skip confirmation (for CI)

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

S3_BUCKET="sigcomply-e2e-tests"
CLOUDTRAIL_NAME="sigcomply-e2e-trail"
CLOUDTRAIL_BUCKET="sigcomply-e2e-cloudtrail-logs"
LOG_GROUP_NAME="sigcomply-e2e-test-logs"
KMS_ALIAS="alias/sigcomply-e2e-test"
ECR_REPO="sigcomply-e2e-test"
RDS_INSTANCE="sigcomply-e2e-test"
DYNAMODB_TABLE="sigcomply-e2e-test"
LAMBDA_FUNCTION="sigcomply-e2e-test"
LAMBDA_ROLE="sigcomply-e2e-lambda-role"
SECRET_NAME="sigcomply-e2e-test-secret"

FORCE=false

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

skip() {
    printf "${YELLOW}[SKIP]${NC} %s\n" "$1"
}

# Check if a command exists
require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        error "Required command not found: $1"
    fi
}

# Parse arguments
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --force|-f)
                FORCE=true
                ;;
            *)
                error "Unknown argument: $1"
                ;;
        esac
        shift
    done
}

# Validate prerequisites
validate_prerequisites() {
    info "Validating prerequisites..."

    require_cmd aws
    require_cmd jq

    local account_id
    account_id=$(aws sts get-caller-identity --query "Account" --output text 2>/dev/null) || \
        error "AWS CLI is not authenticated. Run 'aws configure' or set AWS credentials."

    if [ "$account_id" != "$EXPECTED_ACCOUNT_ID" ]; then
        error "Wrong AWS account. Expected $EXPECTED_ACCOUNT_ID, got $account_id"
    fi

    success "AWS CLI authenticated to account $account_id"
}

# Confirmation prompt
confirm() {
    if [ "$FORCE" = true ]; then
        return
    fi

    echo ""
    warn "This will DELETE the following AWS resources:"
    echo "    - RDS instance: $RDS_INSTANCE"
    echo "    - CloudTrail: $CLOUDTRAIL_NAME"
    echo "    - S3 bucket: $CLOUDTRAIL_BUCKET (emptied + deleted)"
    echo "    - CloudWatch log group: $LOG_GROUP_NAME"
    echo "    - ECR repository: $ECR_REPO"
    echo "    - KMS key: $KMS_ALIAS (scheduled for deletion)"
    echo "    - S3 bucket: $S3_BUCKET (emptied + deleted)"
    echo "    - DynamoDB table: $DYNAMODB_TABLE"
    echo "    - Lambda function: $LAMBDA_FUNCTION (+ role: $LAMBDA_ROLE)"
    echo "    - Secrets Manager secret: $SECRET_NAME"
    echo ""
    warn "IAM users and policies will NOT be deleted."
    echo ""

    printf "Are you sure? (y/N): "
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY])
            ;;
        *)
            info "Aborted."
            exit 0
            ;;
    esac
}

# Delete RDS instance
delete_rds() {
    info "Deleting RDS instance: $RDS_INSTANCE..."

    local status
    status=$(aws rds describe-db-instances --db-instance-identifier "$RDS_INSTANCE" \
        --query "DBInstances[0].DBInstanceStatus" --output text 2>/dev/null) || true

    if [ -z "$status" ] || [ "$status" = "None" ]; then
        skip "RDS instance not found: $RDS_INSTANCE"
        return
    fi

    if [ "$status" = "deleting" ]; then
        info "RDS instance is already being deleted"
        return
    fi

    aws rds delete-db-instance \
        --db-instance-identifier "$RDS_INSTANCE" \
        --skip-final-snapshot \
        --delete-automated-backups >/dev/null
    success "Initiated RDS deletion: $RDS_INSTANCE"
}

# Delete CloudTrail
delete_cloudtrail() {
    info "Deleting CloudTrail: $CLOUDTRAIL_NAME..."

    if ! aws cloudtrail describe-trails --trail-name-list "$CLOUDTRAIL_NAME" \
        --query "trailList[0].Name" --output text 2>/dev/null | grep -q "$CLOUDTRAIL_NAME"; then
        skip "CloudTrail not found: $CLOUDTRAIL_NAME"
        return
    fi

    aws cloudtrail stop-logging --name "$CLOUDTRAIL_NAME" 2>/dev/null || true
    aws cloudtrail delete-trail --name "$CLOUDTRAIL_NAME"
    success "Deleted CloudTrail: $CLOUDTRAIL_NAME"
}

# Empty and delete an S3 bucket
delete_s3_bucket() {
    local bucket="$1"
    info "Deleting S3 bucket: $bucket..."

    if ! aws s3api head-bucket --bucket "$bucket" 2>/dev/null; then
        skip "S3 bucket not found: $bucket"
        return
    fi

    # Empty the bucket (including versioned objects)
    info "Emptying bucket: $bucket..."
    aws s3 rm "s3://$bucket" --recursive 2>/dev/null || true

    # Delete versioned objects if versioning is enabled
    local versions
    versions=$(aws s3api list-object-versions --bucket "$bucket" \
        --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null)
    if [ "$versions" != '{"Objects": null}' ] && [ "$versions" != "null" ] && [ -n "$versions" ]; then
        echo "$versions" | jq -c '.Objects // [] | select(length > 0)' | while read -r objects; do
            if [ "$objects" != "[]" ] && [ -n "$objects" ]; then
                aws s3api delete-objects --bucket "$bucket" \
                    --delete "{\"Objects\": $objects}" >/dev/null 2>&1 || true
            fi
        done
    fi

    # Delete delete markers
    local markers
    markers=$(aws s3api list-object-versions --bucket "$bucket" \
        --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null)
    if [ "$markers" != '{"Objects": null}' ] && [ "$markers" != "null" ] && [ -n "$markers" ]; then
        echo "$markers" | jq -c '.Objects // [] | select(length > 0)' | while read -r objects; do
            if [ "$objects" != "[]" ] && [ -n "$objects" ]; then
                aws s3api delete-objects --bucket "$bucket" \
                    --delete "{\"Objects\": $objects}" >/dev/null 2>&1 || true
            fi
        done
    fi

    aws s3api delete-bucket --bucket "$bucket" --region "$REGION"
    success "Deleted S3 bucket: $bucket"
}

# Delete CloudWatch log group
delete_cloudwatch() {
    info "Deleting CloudWatch log group: $LOG_GROUP_NAME..."

    if ! aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP_NAME" \
        --query "logGroups[?logGroupName=='$LOG_GROUP_NAME'].logGroupName" --output text 2>/dev/null | grep -q "$LOG_GROUP_NAME"; then
        skip "CloudWatch log group not found: $LOG_GROUP_NAME"
        return
    fi

    aws logs delete-log-group --log-group-name "$LOG_GROUP_NAME" --region "$REGION"
    success "Deleted CloudWatch log group: $LOG_GROUP_NAME"
}

# Delete ECR repository
delete_ecr() {
    info "Deleting ECR repository: $ECR_REPO..."

    if ! aws ecr describe-repositories --repository-names "$ECR_REPO" --region "$REGION" >/dev/null 2>&1; then
        skip "ECR repository not found: $ECR_REPO"
        return
    fi

    aws ecr delete-repository \
        --repository-name "$ECR_REPO" \
        --region "$REGION" \
        --force >/dev/null
    success "Deleted ECR repository: $ECR_REPO"
}

# Schedule KMS key deletion
delete_kms() {
    info "Scheduling KMS key deletion: $KMS_ALIAS..."

    local key_id
    key_id=$(aws kms list-aliases --query "Aliases[?AliasName=='$KMS_ALIAS'].TargetKeyId" --output text 2>/dev/null)

    if [ -z "$key_id" ] || [ "$key_id" = "None" ]; then
        skip "KMS key not found: $KMS_ALIAS"
        return
    fi

    # Check if already pending deletion
    local key_state
    key_state=$(aws kms describe-key --key-id "$key_id" --query "KeyMetadata.KeyState" --output text 2>/dev/null)

    if [ "$key_state" = "PendingDeletion" ]; then
        skip "KMS key already pending deletion: $key_id"
        return
    fi

    # Delete alias first
    aws kms delete-alias --alias-name "$KMS_ALIAS" 2>/dev/null || true

    # Schedule key deletion (minimum 7 days)
    aws kms schedule-key-deletion --key-id "$key_id" --pending-window-in-days 7 >/dev/null
    success "Scheduled KMS key deletion (7 days): $key_id"
}

# Delete DynamoDB table
delete_dynamodb() {
    info "Deleting DynamoDB table: $DYNAMODB_TABLE..."

    if ! aws dynamodb describe-table --table-name "$DYNAMODB_TABLE" --region "$REGION" >/dev/null 2>&1; then
        skip "DynamoDB table not found: $DYNAMODB_TABLE"
        return
    fi

    aws dynamodb delete-table --table-name "$DYNAMODB_TABLE" --region "$REGION" >/dev/null
    success "Deleted DynamoDB table: $DYNAMODB_TABLE"
}

# Delete Lambda function and execution role
delete_lambda() {
    info "Deleting Lambda function: $LAMBDA_FUNCTION..."

    if aws lambda get-function --function-name "$LAMBDA_FUNCTION" --region "$REGION" >/dev/null 2>&1; then
        aws lambda delete-function --function-name "$LAMBDA_FUNCTION" --region "$REGION" >/dev/null
        success "Deleted Lambda function: $LAMBDA_FUNCTION"
    else
        skip "Lambda function not found: $LAMBDA_FUNCTION"
    fi

    info "Deleting Lambda execution role: $LAMBDA_ROLE..."
    if aws iam get-role --role-name "$LAMBDA_ROLE" >/dev/null 2>&1; then
        # Detach all managed policies before deleting the role
        local policies
        policies=$(aws iam list-attached-role-policies --role-name "$LAMBDA_ROLE" \
            --query "AttachedPolicies[].PolicyArn" --output text 2>/dev/null) || true
        for policy_arn in $policies; do
            if [ -n "$policy_arn" ] && [ "$policy_arn" != "None" ]; then
                aws iam detach-role-policy --role-name "$LAMBDA_ROLE" --policy-arn "$policy_arn" 2>/dev/null || true
            fi
        done
        aws iam delete-role --role-name "$LAMBDA_ROLE" >/dev/null
        success "Deleted Lambda execution role: $LAMBDA_ROLE"
    else
        skip "Lambda execution role not found: $LAMBDA_ROLE"
    fi
}

# Delete Secrets Manager secret
delete_secrets_manager() {
    info "Deleting Secrets Manager secret: $SECRET_NAME..."

    if ! aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --region "$REGION" >/dev/null 2>&1; then
        skip "Secrets Manager secret not found: $SECRET_NAME"
        return
    fi

    aws secretsmanager delete-secret \
        --secret-id "$SECRET_NAME" \
        --force-delete-without-recovery \
        --region "$REGION" >/dev/null
    success "Deleted Secrets Manager secret: $SECRET_NAME"
}

# Wait for RDS deletion
wait_for_rds_deletion() {
    local status
    status=$(aws rds describe-db-instances --db-instance-identifier "$RDS_INSTANCE" \
        --query "DBInstances[0].DBInstanceStatus" --output text 2>/dev/null) || true

    if [ -z "$status" ] || [ "$status" = "None" ]; then
        return
    fi

    info "Waiting for RDS deletion to complete (status: $status)..."
    info "This can take 5-10 minutes..."

    local elapsed=0
    local timeout=900

    while [ $elapsed -lt $timeout ]; do
        status=$(aws rds describe-db-instances --db-instance-identifier "$RDS_INSTANCE" \
            --query "DBInstances[0].DBInstanceStatus" --output text 2>/dev/null) || true

        if [ -z "$status" ] || [ "$status" = "None" ]; then
            success "RDS instance deleted"
            return
        fi

        printf "."
        sleep 30
        elapsed=$((elapsed + 30))
    done

    echo ""
    warn "RDS deletion not yet complete after ${timeout}s. It will continue in the background."
}

# Print summary
print_summary() {
    echo ""
    echo "  ========================================"
    echo "  SigComply E2E AWS Teardown Complete"
    echo "  ========================================"
    echo ""
    echo "  Deleted resources:"
    echo "    - RDS instance: $RDS_INSTANCE"
    echo "    - CloudTrail: $CLOUDTRAIL_NAME"
    echo "    - S3 bucket: $CLOUDTRAIL_BUCKET"
    echo "    - CloudWatch log group: $LOG_GROUP_NAME"
    echo "    - ECR repository: $ECR_REPO"
    echo "    - KMS key: $KMS_ALIAS (scheduled, 7-day wait)"
    echo "    - DynamoDB table: $DYNAMODB_TABLE"
    echo "    - Lambda function: $LAMBDA_FUNCTION (+ role: $LAMBDA_ROLE)"
    echo "    - Secrets Manager secret: $SECRET_NAME"
    echo "    - S3 bucket: $S3_BUCKET"
    echo ""
    echo "  NOT deleted (long-lived):"
    echo "    - IAM users (sigcomply-e2e-*)"
    echo "    - IAM policies (sigcomply-e2e-*-policy)"
    echo "    - Access keys (would require redistribution)"
    echo ""
}

# Main
main() {
    echo ""
    echo "  SigComply E2E AWS Teardown"
    echo "  =========================="
    echo ""

    parse_args "$@"
    validate_prerequisites
    confirm

    delete_rds
    delete_cloudtrail
    delete_s3_bucket "$CLOUDTRAIL_BUCKET"
    delete_cloudwatch
    delete_ecr
    delete_kms
    delete_dynamodb
    delete_lambda
    delete_secrets_manager
    delete_s3_bucket "$S3_BUCKET"
    wait_for_rds_deletion
    print_summary
}

main "$@"
