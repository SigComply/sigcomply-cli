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
SNS_TOPIC_NAME="sigcomply-e2e-test"
SQS_QUEUE_NAME="sigcomply-e2e-test"
EFS_NAME="sigcomply-e2e-test"
BACKUP_VAULT_NAME="sigcomply-e2e-test"

# New resources
LAUNCH_TEMPLATE_NAME="sigcomply-e2e-test"
EC2_INSTANCE_NAME="sigcomply-e2e-test"
EBS_VOLUME_NAME="sigcomply-e2e-test"
ECS_CLUSTER_NAME="sigcomply-e2e-test"
ECS_TASK_FAMILY="sigcomply-e2e-test"
ASG_NAME="sigcomply-e2e-test"
CLOUDFRONT_COMMENT="sigcomply-e2e-test"
APIGATEWAY_REST_NAME="sigcomply-e2e-test"
APIGATEWAY_V2_NAME="sigcomply-e2e-test"
ROUTE53_ZONE_NAME="sigcomply-e2e-test.internal"
CODEBUILD_PROJECT="sigcomply-e2e-test"
CODEBUILD_ROLE="sigcomply-e2e-codebuild-role"
KINESIS_STREAM="sigcomply-e2e-test"
COGNITO_POOL_NAME="sigcomply-e2e-test"
SFN_STATE_MACHINE="sigcomply-e2e-test"
SFN_ROLE="sigcomply-e2e-sfn-role"
APPSYNC_API_NAME="sigcomply-e2e-test"
ATHENA_WORKGROUP="sigcomply-e2e-test"
GLUE_JOB_NAME="sigcomply-e2e-test"
GLUE_ROLE="sigcomply-e2e-glue-role"

# Expensive resources
EKS_CLUSTER_NAME="sigcomply-e2e-test"
EKS_ROLE="sigcomply-e2e-eks-role"
MSK_CLUSTER_NAME="sigcomply-e2e-test"
NEPTUNE_CLUSTER="sigcomply-e2e-test"
NEPTUNE_INSTANCE="sigcomply-e2e-test"
NEPTUNE_SUBNET_GROUP="sigcomply-e2e-test"
OPENSEARCH_DOMAIN="sigcomply-e2e"
REDSHIFT_CLUSTER="sigcomply-e2e-test"
REDSHIFT_SUBNET_GROUP="sigcomply-e2e-test"
REDSHIFT_SL_NAMESPACE="sigcomply-e2e-test"
REDSHIFT_SL_WORKGROUP="sigcomply-e2e-test"
EMR_CLUSTER_NAME="sigcomply-e2e-test"
EMR_ROLE="sigcomply-e2e-emr-role"
EMR_EC2_ROLE="sigcomply-e2e-emr-ec2-role"
EMR_INSTANCE_PROFILE="sigcomply-e2e-emr-ec2-profile"
DOCDB_CLUSTER="sigcomply-e2e-test"
DOCDB_INSTANCE="sigcomply-e2e-test"
DOCDB_SUBNET_GROUP="sigcomply-e2e-docdb"
MQ_BROKER_NAME="sigcomply-e2e-test"
DMS_INSTANCE="sigcomply-e2e-test"
DMS_SUBNET_GROUP="sigcomply-e2e-test"
NFW_FIREWALL="sigcomply-e2e-test"
NFW_POLICY="sigcomply-e2e-test"
FSX_NAME="sigcomply-e2e-test"
TRANSFER_SERVER="sigcomply-e2e-test"
SAGEMAKER_NOTEBOOK="sigcomply-e2e-test"
SAGEMAKER_ROLE="sigcomply-e2e-sagemaker-role"
DAX_CLUSTER="sigcomply-e2e-test"
DAX_SUBNET_GROUP="sigcomply-e2e-test"
DAX_ROLE="sigcomply-e2e-dax-role"
EB_APP_NAME="sigcomply-e2e-test"
EB_ENV_NAME="sigcomply-e2e-test"
DATASYNC_TASK_NAME="sigcomply-e2e-test"
DB_SUBNET_GROUP="sigcomply-e2e-test"

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
    echo "    - SNS topic: $SNS_TOPIC_NAME"
    echo "    - SQS queue: $SQS_QUEUE_NAME"
    echo "    - EFS filesystem: $EFS_NAME"
    echo "    - Backup vault: $BACKUP_VAULT_NAME"
    echo "    - VPC flow logs (on default VPC)"
    echo "    - ASG: $ASG_NAME"
    echo "    - EC2 instance: $EC2_INSTANCE_NAME"
    echo "    - EBS snapshot + volume: $EBS_VOLUME_NAME"
    echo "    - Launch Template: $LAUNCH_TEMPLATE_NAME"
    echo "    - VPC S3 gateway endpoint"
    echo "    - ECS cluster + task defs: $ECS_CLUSTER_NAME"
    echo "    - CloudFront distribution (disable + wait + delete)"
    echo "    - API Gateway REST: $APIGATEWAY_REST_NAME"
    echo "    - API Gateway V2: $APIGATEWAY_V2_NAME"
    echo "    - CodeBuild: $CODEBUILD_PROJECT (+ role)"
    echo "    - Kinesis: $KINESIS_STREAM"
    echo "    - Cognito: $COGNITO_POOL_NAME"
    echo "    - ACM certificate (self-signed)"
    echo "    - Glue job: $GLUE_JOB_NAME (+ role)"
    echo "    - Step Functions: $SFN_STATE_MACHINE (+ role)"
    echo "    - Route53 zone: $ROUTE53_ZONE_NAME"
    echo "    - AppSync: $APPSYNC_API_NAME"
    echo "    - Athena: $ATHENA_WORKGROUP"
    echo ""
    echo "  Expensive resources (per-hour billing):"
    echo "    - EKS: $EKS_CLUSTER_NAME (+ role)"
    echo "    - MSK: $MSK_CLUSTER_NAME"
    echo "    - Neptune: $NEPTUNE_CLUSTER (+ instance + subnet group)"
    echo "    - OpenSearch: $OPENSEARCH_DOMAIN"
    echo "    - Redshift: $REDSHIFT_CLUSTER (+ subnet group)"
    echo "    - Redshift Serverless: $REDSHIFT_SL_NAMESPACE/$REDSHIFT_SL_WORKGROUP"
    echo "    - EMR: $EMR_CLUSTER_NAME (+ roles + instance profile)"
    echo "    - DocumentDB: $DOCDB_CLUSTER (+ instance + subnet group)"
    echo "    - Amazon MQ: $MQ_BROKER_NAME"
    echo "    - DMS: $DMS_INSTANCE (+ subnet group)"
    echo "    - Network Firewall: $NFW_FIREWALL (+ policy)"
    echo "    - FSx: $FSX_NAME"
    echo "    - Transfer: $TRANSFER_SERVER"
    echo "    - SageMaker: $SAGEMAKER_NOTEBOOK (+ role)"
    echo "    - DAX: $DAX_CLUSTER (+ subnet group + role)"
    echo "    - Elastic Beanstalk: $EB_APP_NAME/$EB_ENV_NAME"
    echo "    - DataSync: $DATASYNC_TASK_NAME"
    echo "    - Shared DB subnet group: $DB_SUBNET_GROUP"
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

# Delete SNS topic
delete_sns() {
    info "Deleting SNS topic: $SNS_TOPIC_NAME..."

    local topic_arn
    topic_arn=$(aws sns list-topics --region "$REGION" --query "Topics[?ends_with(TopicArn, ':$SNS_TOPIC_NAME')].TopicArn | [0]" --output text 2>/dev/null) || true

    if [ -z "$topic_arn" ] || [ "$topic_arn" = "None" ] || [ "$topic_arn" = "null" ]; then
        skip "SNS topic not found: $SNS_TOPIC_NAME"
        return
    fi

    aws sns delete-topic --topic-arn "$topic_arn" --region "$REGION"
    success "Deleted SNS topic: $SNS_TOPIC_NAME"
}

# Delete SQS queue
delete_sqs() {
    info "Deleting SQS queue: $SQS_QUEUE_NAME..."

    local queue_url
    queue_url=$(aws sqs get-queue-url --queue-name "$SQS_QUEUE_NAME" --region "$REGION" --query "QueueUrl" --output text 2>/dev/null) || true

    if [ -z "$queue_url" ] || [ "$queue_url" = "None" ] || [ "$queue_url" = "null" ]; then
        skip "SQS queue not found: $SQS_QUEUE_NAME"
        return
    fi

    aws sqs delete-queue --queue-url "$queue_url" --region "$REGION"
    success "Deleted SQS queue: $SQS_QUEUE_NAME"
}

# Delete EFS filesystem
delete_efs() {
    info "Deleting EFS filesystem: $EFS_NAME..."

    local fs_id
    fs_id=$(aws efs describe-file-systems --region "$REGION" \
        --query "FileSystems[?Name=='$EFS_NAME'].FileSystemId | [0]" --output text 2>/dev/null) || true

    if [ -z "$fs_id" ] || [ "$fs_id" = "None" ] || [ "$fs_id" = "null" ]; then
        skip "EFS filesystem not found: $EFS_NAME"
        return
    fi

    # Delete mount targets first (required before filesystem deletion)
    local mount_targets
    mount_targets=$(aws efs describe-mount-targets --file-system-id "$fs_id" --region "$REGION" \
        --query "MountTargets[].MountTargetId" --output text 2>/dev/null) || true
    for mt in $mount_targets; do
        if [ -n "$mt" ] && [ "$mt" != "None" ]; then
            aws efs delete-mount-target --mount-target-id "$mt" --region "$REGION" 2>/dev/null || true
        fi
    done

    # Wait briefly for mount targets to be deleted
    if [ -n "$mount_targets" ] && [ "$mount_targets" != "None" ]; then
        sleep 5
    fi

    aws efs delete-file-system --file-system-id "$fs_id" --region "$REGION"
    success "Deleted EFS filesystem: $EFS_NAME ($fs_id)"
}

# Delete Backup vault
delete_backup_vault() {
    info "Deleting Backup vault: $BACKUP_VAULT_NAME..."

    if ! aws backup describe-backup-vault --backup-vault-name "$BACKUP_VAULT_NAME" --region "$REGION" >/dev/null 2>&1; then
        skip "Backup vault not found: $BACKUP_VAULT_NAME"
        return
    fi

    aws backup delete-backup-vault \
        --backup-vault-name "$BACKUP_VAULT_NAME" \
        --region "$REGION"
    success "Deleted Backup vault: $BACKUP_VAULT_NAME"
}

# Delete VPC flow logs
delete_vpc_flow_logs() {
    info "Deleting VPC flow logs..."

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION") || true

    if [ -z "$vpc_id" ] || [ "$vpc_id" = "None" ]; then
        skip "No default VPC found"
        return
    fi

    local flow_log_ids
    flow_log_ids=$(aws ec2 describe-flow-logs \
        --filter "Name=resource-id,Values=$vpc_id" \
        --query "FlowLogs[].FlowLogId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$flow_log_ids" ] || [ "$flow_log_ids" = "None" ]; then
        skip "No VPC flow logs found for $vpc_id"
        return
    fi

    # shellcheck disable=SC2086
    aws ec2 delete-flow-logs --flow-log-ids $flow_log_ids --region "$REGION" >/dev/null
    success "Deleted VPC flow logs for $vpc_id"

    # Clean up log group
    local flow_log_group="sigcomply-e2e-vpc-flow-logs"
    if aws logs describe-log-groups --log-group-name-prefix "$flow_log_group" \
        --query "logGroups[?logGroupName=='$flow_log_group'].logGroupName" --output text 2>/dev/null | grep -q "$flow_log_group"; then
        aws logs delete-log-group --log-group-name "$flow_log_group" --region "$REGION"
        success "Deleted flow logs log group: $flow_log_group"
    fi

    # Clean up flow log IAM role
    local flow_log_role="sigcomply-e2e-flow-log-role"
    if aws iam get-role --role-name "$flow_log_role" >/dev/null 2>&1; then
        aws iam delete-role-policy --role-name "$flow_log_role" --policy-name "flow-log-cloudwatch-access" 2>/dev/null || true
        aws iam delete-role --role-name "$flow_log_role" >/dev/null
        success "Deleted flow log IAM role: $flow_log_role"
    fi
}

# Helper: delete IAM service role
delete_service_role() {
    local role_name="$1"
    info "Deleting IAM role: $role_name..."

    if ! aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
        skip "IAM role not found: $role_name"
        return
    fi

    # Detach managed policies
    local policies
    policies=$(aws iam list-attached-role-policies --role-name "$role_name" \
        --query "AttachedPolicies[].PolicyArn" --output text 2>/dev/null) || true
    for policy_arn in $policies; do
        if [ -n "$policy_arn" ] && [ "$policy_arn" != "None" ]; then
            aws iam detach-role-policy --role-name "$role_name" --policy-arn "$policy_arn" 2>/dev/null || true
        fi
    done

    # Delete inline policies
    local inline_policies
    inline_policies=$(aws iam list-role-policies --role-name "$role_name" \
        --query "PolicyNames" --output text 2>/dev/null) || true
    for pol_name in $inline_policies; do
        if [ -n "$pol_name" ] && [ "$pol_name" != "None" ]; then
            aws iam delete-role-policy --role-name "$role_name" --policy-name "$pol_name" 2>/dev/null || true
        fi
    done

    aws iam delete-role --role-name "$role_name" >/dev/null
    success "Deleted IAM role: $role_name"
}

# Delete ASG
delete_asg() {
    info "Deleting ASG: $ASG_NAME..."

    if ! aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$ASG_NAME" \
        --query "AutoScalingGroups[0].AutoScalingGroupName" --output text --region "$REGION" 2>/dev/null | grep -q "$ASG_NAME"; then
        skip "ASG not found: $ASG_NAME"
        return
    fi

    # Force delete (sets desired/min to 0 automatically)
    aws autoscaling delete-auto-scaling-group \
        --auto-scaling-group-name "$ASG_NAME" \
        --force-delete \
        --region "$REGION"
    success "Deleted ASG: $ASG_NAME"
}

# Terminate EC2 instance
delete_ec2_instance() {
    info "Terminating EC2 instance: $EC2_INSTANCE_NAME..."

    local instance_id
    instance_id=$(aws ec2 describe-instances \
        --filters "Name=tag:Name,Values=$EC2_INSTANCE_NAME" "Name=instance-state-name,Values=running,pending,stopped,stopping" \
        --query "Reservations[0].Instances[0].InstanceId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$instance_id" ] || [ "$instance_id" = "None" ]; then
        skip "EC2 instance not found: $EC2_INSTANCE_NAME"
        return
    fi

    aws ec2 terminate-instances --instance-ids "$instance_id" --region "$REGION" >/dev/null
    success "Terminated EC2 instance: $EC2_INSTANCE_NAME ($instance_id)"

    # Wait for termination to complete (needed before snapshot/volume deletion)
    info "Waiting for instance termination..."
    aws ec2 wait instance-terminated --instance-ids "$instance_id" --region "$REGION" 2>/dev/null || true
    success "EC2 instance terminated"
}

# Delete EBS snapshot
delete_ebs_snapshot() {
    info "Deleting EBS snapshot..."

    local snapshot_id
    snapshot_id=$(aws ec2 describe-snapshots --owner-ids self \
        --filters "Name=tag:Name,Values=$EBS_VOLUME_NAME-snapshot" \
        --query "Snapshots[0].SnapshotId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$snapshot_id" ] || [ "$snapshot_id" = "None" ]; then
        skip "EBS snapshot not found"
        return
    fi

    aws ec2 delete-snapshot --snapshot-id "$snapshot_id" --region "$REGION"
    success "Deleted EBS snapshot: $snapshot_id"
}

# Delete EBS volume
delete_ebs_volume() {
    info "Deleting EBS volume: $EBS_VOLUME_NAME..."

    local volume_id
    volume_id=$(aws ec2 describe-volumes \
        --filters "Name=tag:Name,Values=$EBS_VOLUME_NAME" \
        --query "Volumes[0].VolumeId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$volume_id" ] || [ "$volume_id" = "None" ]; then
        skip "EBS volume not found: $EBS_VOLUME_NAME"
        return
    fi

    aws ec2 delete-volume --volume-id "$volume_id" --region "$REGION"
    success "Deleted EBS volume: $EBS_VOLUME_NAME ($volume_id)"
}

# Delete EC2 Launch Template
delete_launch_template() {
    info "Deleting Launch Template: $LAUNCH_TEMPLATE_NAME..."

    if ! aws ec2 describe-launch-templates --launch-template-names "$LAUNCH_TEMPLATE_NAME" \
        --region "$REGION" >/dev/null 2>&1; then
        skip "Launch Template not found: $LAUNCH_TEMPLATE_NAME"
        return
    fi

    aws ec2 delete-launch-template --launch-template-name "$LAUNCH_TEMPLATE_NAME" --region "$REGION" >/dev/null
    success "Deleted Launch Template: $LAUNCH_TEMPLATE_NAME"
}

# Delete VPC Endpoint
delete_vpc_endpoint() {
    info "Deleting VPC S3 gateway endpoint..."

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION") || true

    if [ -z "$vpc_id" ] || [ "$vpc_id" = "None" ]; then
        skip "No default VPC found"
        return
    fi

    local endpoint_id
    endpoint_id=$(aws ec2 describe-vpc-endpoints \
        --filters "Name=vpc-id,Values=$vpc_id" "Name=service-name,Values=com.amazonaws.$REGION.s3" "Name=vpc-endpoint-type,Values=Gateway" \
        --query "VpcEndpoints[0].VpcEndpointId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$endpoint_id" ] || [ "$endpoint_id" = "None" ]; then
        skip "VPC S3 gateway endpoint not found"
        return
    fi

    aws ec2 delete-vpc-endpoints --vpc-endpoint-ids "$endpoint_id" --region "$REGION" >/dev/null
    success "Deleted VPC endpoint: $endpoint_id"
}

# Delete ECS cluster and task definitions
delete_ecs() {
    info "Deleting ECS resources..."

    # Deregister task definitions
    local task_def_arns
    task_def_arns=$(aws ecs list-task-definitions --family-prefix "$ECS_TASK_FAMILY" \
        --query "taskDefinitionArns" --output text --region "$REGION" 2>/dev/null) || true

    for arn in $task_def_arns; do
        if [ -n "$arn" ] && [ "$arn" != "None" ]; then
            aws ecs deregister-task-definition --task-definition "$arn" --region "$REGION" >/dev/null 2>&1 || true
        fi
    done
    if [ -n "$task_def_arns" ] && [ "$task_def_arns" != "None" ]; then
        success "Deregistered ECS task definitions: $ECS_TASK_FAMILY"
    fi

    # Delete cluster
    if aws ecs describe-clusters --clusters "$ECS_CLUSTER_NAME" --region "$REGION" \
        --query "clusters[?status=='ACTIVE'].clusterName" --output text 2>/dev/null | grep -q "$ECS_CLUSTER_NAME"; then
        aws ecs delete-cluster --cluster "$ECS_CLUSTER_NAME" --region "$REGION" >/dev/null
        success "Deleted ECS cluster: $ECS_CLUSTER_NAME"
    else
        skip "ECS cluster not found: $ECS_CLUSTER_NAME"
    fi
}

# Delete CloudFront distribution (disable first, wait, then delete)
delete_cloudfront() {
    info "Deleting CloudFront distribution..."

    local dist_id
    dist_id=$(aws cloudfront list-distributions \
        --query "DistributionList.Items[?Comment=='$CLOUDFRONT_COMMENT'].Id | [0]" --output text 2>/dev/null) || true

    if [ -z "$dist_id" ] || [ "$dist_id" = "None" ] || [ "$dist_id" = "null" ]; then
        skip "CloudFront distribution not found"
        return
    fi

    # Get current config and ETag
    local config_output
    config_output=$(aws cloudfront get-distribution-config --id "$dist_id" --output json)
    local etag
    etag=$(echo "$config_output" | jq -r '.ETag')
    local dist_config
    dist_config=$(echo "$config_output" | jq '.DistributionConfig')

    # Check if already disabled
    local enabled
    enabled=$(echo "$dist_config" | jq -r '.Enabled')

    if [ "$enabled" = "true" ]; then
        # Disable the distribution
        local disabled_config
        disabled_config=$(echo "$dist_config" | jq '.Enabled = false')

        local update_output
        update_output=$(aws cloudfront update-distribution \
            --id "$dist_id" \
            --distribution-config "$disabled_config" \
            --if-match "$etag" --output json)
        etag=$(echo "$update_output" | jq -r '.ETag')

        info "Disabled CloudFront distribution $dist_id. Waiting for deployment..."
        aws cloudfront wait distribution-deployed --id "$dist_id" 2>/dev/null || {
            warn "CloudFront wait timed out. Distribution may still be deploying."
            warn "Re-run teardown later to complete deletion."
            return
        }
    fi

    # Get fresh ETag after disable
    etag=$(aws cloudfront get-distribution-config --id "$dist_id" --query "ETag" --output text)

    aws cloudfront delete-distribution --id "$dist_id" --if-match "$etag"
    success "Deleted CloudFront distribution: $dist_id"
}

# Delete API Gateway REST API
delete_apigateway_rest() {
    info "Deleting API Gateway REST API: $APIGATEWAY_REST_NAME..."

    local api_id
    api_id=$(aws apigateway get-rest-apis \
        --query "items[?name=='$APIGATEWAY_REST_NAME'].id | [0]" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$api_id" ] || [ "$api_id" = "None" ] || [ "$api_id" = "null" ]; then
        skip "API Gateway REST API not found: $APIGATEWAY_REST_NAME"
        return
    fi

    aws apigateway delete-rest-api --rest-api-id "$api_id" --region "$REGION"
    success "Deleted API Gateway REST API: $APIGATEWAY_REST_NAME ($api_id)"
}

# Delete API Gateway V2 HTTP API
delete_apigateway_v2() {
    info "Deleting API Gateway V2 HTTP API: $APIGATEWAY_V2_NAME..."

    local api_id
    api_id=$(aws apigatewayv2 get-apis \
        --query "Items[?Name=='$APIGATEWAY_V2_NAME'].ApiId | [0]" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$api_id" ] || [ "$api_id" = "None" ] || [ "$api_id" = "null" ]; then
        skip "API Gateway V2 HTTP API not found: $APIGATEWAY_V2_NAME"
        return
    fi

    aws apigatewayv2 delete-api --api-id "$api_id" --region "$REGION"
    success "Deleted API Gateway V2 HTTP API: $APIGATEWAY_V2_NAME ($api_id)"
}

# Delete CodeBuild project and role
delete_codebuild() {
    info "Deleting CodeBuild project: $CODEBUILD_PROJECT..."

    if aws codebuild batch-get-projects --names "$CODEBUILD_PROJECT" \
        --query "projects[0].name" --output text --region "$REGION" 2>/dev/null | grep -q "$CODEBUILD_PROJECT"; then
        aws codebuild delete-project --name "$CODEBUILD_PROJECT" --region "$REGION" >/dev/null
        success "Deleted CodeBuild project: $CODEBUILD_PROJECT"
    else
        skip "CodeBuild project not found: $CODEBUILD_PROJECT"
    fi

    delete_service_role "$CODEBUILD_ROLE"
}

# Delete Kinesis stream
delete_kinesis() {
    info "Deleting Kinesis stream: $KINESIS_STREAM..."

    if ! aws kinesis describe-stream-summary --stream-name "$KINESIS_STREAM" \
        --region "$REGION" >/dev/null 2>&1; then
        skip "Kinesis stream not found: $KINESIS_STREAM"
        return
    fi

    aws kinesis delete-stream --stream-name "$KINESIS_STREAM" --region "$REGION"
    success "Deleted Kinesis stream: $KINESIS_STREAM"
}

# Delete Cognito User Pool
delete_cognito() {
    info "Deleting Cognito User Pool: $COGNITO_POOL_NAME..."

    local pool_id
    pool_id=$(aws cognito-idp list-user-pools --max-results 60 --region "$REGION" \
        --query "UserPools[?Name=='$COGNITO_POOL_NAME'].Id | [0]" --output text 2>/dev/null) || true

    if [ -z "$pool_id" ] || [ "$pool_id" = "None" ] || [ "$pool_id" = "null" ]; then
        skip "Cognito User Pool not found: $COGNITO_POOL_NAME"
        return
    fi

    aws cognito-idp delete-user-pool --user-pool-id "$pool_id" --region "$REGION"
    success "Deleted Cognito User Pool: $COGNITO_POOL_NAME ($pool_id)"
}

# Delete ACM certificate
delete_acm() {
    info "Deleting ACM certificate..."

    local cert_arn
    cert_arn=$(aws acm list-certificates --region "$REGION" \
        --query "CertificateSummaryList[?DomainName=='sigcomply-e2e-test.example.com'].CertificateArn | [0]" --output text 2>/dev/null) || true

    if [ -z "$cert_arn" ] || [ "$cert_arn" = "None" ] || [ "$cert_arn" = "null" ]; then
        skip "ACM certificate not found"
        return
    fi

    aws acm delete-certificate --certificate-arn "$cert_arn" --region "$REGION"
    success "Deleted ACM certificate: $cert_arn"
}

# Delete Glue job and role
delete_glue() {
    info "Deleting Glue job: $GLUE_JOB_NAME..."

    if aws glue get-jobs --region "$REGION" \
        --query "Jobs[?Name=='$GLUE_JOB_NAME'].Name | [0]" --output text 2>/dev/null | grep -q "$GLUE_JOB_NAME"; then
        aws glue delete-job --job-name "$GLUE_JOB_NAME" --region "$REGION" >/dev/null
        success "Deleted Glue job: $GLUE_JOB_NAME"
    else
        skip "Glue job not found: $GLUE_JOB_NAME"
    fi

    delete_service_role "$GLUE_ROLE"
}

# Delete Step Functions state machine and role
delete_stepfunctions() {
    info "Deleting Step Functions state machine: $SFN_STATE_MACHINE..."

    local sm_arn
    sm_arn=$(aws stepfunctions list-state-machines --region "$REGION" \
        --query "stateMachines[?name=='$SFN_STATE_MACHINE'].stateMachineArn | [0]" --output text 2>/dev/null) || true

    if [ -n "$sm_arn" ] && [ "$sm_arn" != "None" ] && [ "$sm_arn" != "null" ]; then
        aws stepfunctions delete-state-machine --state-machine-arn "$sm_arn" --region "$REGION"
        success "Deleted Step Functions state machine: $SFN_STATE_MACHINE"
    else
        skip "Step Functions state machine not found: $SFN_STATE_MACHINE"
    fi

    delete_service_role "$SFN_ROLE"
}

# Delete Route53 private hosted zone
delete_route53() {
    info "Deleting Route53 zone: $ROUTE53_ZONE_NAME..."

    local zone_id
    zone_id=$(aws route53 list-hosted-zones-by-name --dns-name "$ROUTE53_ZONE_NAME" \
        --query "HostedZones[?Name=='${ROUTE53_ZONE_NAME}.'].Id | [0]" --output text 2>/dev/null) || true

    if [ -z "$zone_id" ] || [ "$zone_id" = "None" ] || [ "$zone_id" = "null" ]; then
        skip "Route53 zone not found: $ROUTE53_ZONE_NAME"
        return
    fi

    # Clean zone_id (remove /hostedzone/ prefix)
    zone_id=$(echo "$zone_id" | sed 's|/hostedzone/||')

    # Delete all non-NS/SOA records first
    local changes
    changes=$(aws route53 list-resource-record-sets --hosted-zone-id "$zone_id" \
        --query "ResourceRecordSets[?Type != 'NS' && Type != 'SOA']" --output json 2>/dev/null)

    local record_count
    record_count=$(echo "$changes" | jq 'length')

    if [ "$record_count" -gt 0 ]; then
        local change_batch
        change_batch=$(echo "$changes" | jq '{Changes: [.[] | {Action: "DELETE", ResourceRecordSet: .}]}')
        aws route53 change-resource-record-sets \
            --hosted-zone-id "$zone_id" \
            --change-batch "$change_batch" >/dev/null 2>&1 || true
        info "Deleted $record_count record sets from zone"
    fi

    aws route53 delete-hosted-zone --id "$zone_id" >/dev/null
    success "Deleted Route53 zone: $ROUTE53_ZONE_NAME ($zone_id)"
}

# Delete AppSync API
delete_appsync() {
    info "Deleting AppSync API: $APPSYNC_API_NAME..."

    local api_id
    api_id=$(aws appsync list-graphql-apis --region "$REGION" \
        --query "graphqlApis[?name=='$APPSYNC_API_NAME'].apiId | [0]" --output text 2>/dev/null) || true

    if [ -z "$api_id" ] || [ "$api_id" = "None" ] || [ "$api_id" = "null" ]; then
        skip "AppSync API not found: $APPSYNC_API_NAME"
        return
    fi

    aws appsync delete-graphql-api --api-id "$api_id" --region "$REGION"
    success "Deleted AppSync API: $APPSYNC_API_NAME ($api_id)"
}

# Delete Athena workgroup
delete_athena() {
    info "Deleting Athena workgroup: $ATHENA_WORKGROUP..."

    if ! aws athena get-work-group --work-group "$ATHENA_WORKGROUP" \
        --region "$REGION" >/dev/null 2>&1; then
        skip "Athena workgroup not found: $ATHENA_WORKGROUP"
        return
    fi

    aws athena delete-work-group --work-group "$ATHENA_WORKGROUP" \
        --recursive-delete-option --region "$REGION"
    success "Deleted Athena workgroup: $ATHENA_WORKGROUP"
}

# =============================================================================
# Expensive services teardown
# =============================================================================

# Delete DataSync task and locations
delete_datasync() {
    info "Deleting DataSync task: $DATASYNC_TASK_NAME..."

    local task_arn
    task_arn=$(aws datasync list-tasks --region "$REGION" \
        --query "Tasks[?Tags[?Key=='Name' && Value=='$DATASYNC_TASK_NAME']].TaskArn | [0]" --output text 2>/dev/null) || true

    if [ -n "$task_arn" ] && [ "$task_arn" != "None" ] && [ "$task_arn" != "null" ]; then
        aws datasync delete-task --task-arn "$task_arn" --region "$REGION"
        success "Deleted DataSync task: $DATASYNC_TASK_NAME"
    else
        skip "DataSync task not found: $DATASYNC_TASK_NAME"
    fi

    # Clean up locations
    local locations
    locations=$(aws datasync list-locations --region "$REGION" \
        --query "Locations[?contains(LocationUri, 'sigcomply-e2e')].LocationArn" --output text 2>/dev/null) || true
    for loc in $locations; do
        if [ -n "$loc" ] && [ "$loc" != "None" ]; then
            aws datasync delete-location --location-arn "$loc" --region "$REGION" 2>/dev/null || true
        fi
    done
}

# Delete Elastic Beanstalk environment and app
delete_elasticbeanstalk() {
    info "Deleting Elastic Beanstalk: $EB_APP_NAME..."

    local env_status
    env_status=$(aws elasticbeanstalk describe-environments \
        --application-name "$EB_APP_NAME" \
        --environment-names "$EB_ENV_NAME" \
        --query "Environments[?Status!='Terminated'].Status | [0]" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$env_status" ] && [ "$env_status" != "None" ] && [ "$env_status" != "null" ]; then
        aws elasticbeanstalk terminate-environment \
            --environment-name "$EB_ENV_NAME" \
            --region "$REGION" >/dev/null
        success "Initiated Elastic Beanstalk environment termination: $EB_ENV_NAME"
        info "Waiting for environment termination (this may take a few minutes)..."
        # Don't block — environment will terminate in background
    else
        skip "Elastic Beanstalk environment not found or already terminated: $EB_ENV_NAME"
    fi

    # Delete application (will succeed once environment is terminated)
    if aws elasticbeanstalk describe-applications --application-names "$EB_APP_NAME" \
        --query "Applications[0].ApplicationName" --output text --region "$REGION" 2>/dev/null | grep -q "$EB_APP_NAME"; then
        aws elasticbeanstalk delete-application \
            --application-name "$EB_APP_NAME" \
            --terminate-env-by-force \
            --region "$REGION" 2>/dev/null || true
        success "Deleted Elastic Beanstalk app: $EB_APP_NAME"
    fi
}

# Delete DAX cluster and subnet group
delete_dax() {
    info "Deleting DAX cluster: $DAX_CLUSTER..."

    if aws dax describe-clusters --cluster-names "$DAX_CLUSTER" \
        --region "$REGION" >/dev/null 2>&1; then
        aws dax delete-cluster --cluster-name "$DAX_CLUSTER" --region "$REGION" >/dev/null
        success "Initiated DAX cluster deletion: $DAX_CLUSTER"
    else
        skip "DAX cluster not found: $DAX_CLUSTER"
    fi

    # Delete subnet group (may need to wait for cluster deletion)
    if aws dax describe-subnet-groups --subnet-group-names "$DAX_SUBNET_GROUP" \
        --region "$REGION" >/dev/null 2>&1; then
        aws dax delete-subnet-group --subnet-group-name "$DAX_SUBNET_GROUP" \
            --region "$REGION" 2>/dev/null || warn "DAX subnet group in use, will be cleaned up after cluster deletes"
    fi

    delete_service_role "$DAX_ROLE"
}

# Delete SageMaker notebook instance
delete_sagemaker() {
    info "Deleting SageMaker notebook: $SAGEMAKER_NOTEBOOK..."

    local status
    status=$(aws sagemaker describe-notebook-instance --notebook-instance-name "$SAGEMAKER_NOTEBOOK" \
        --query "NotebookInstanceStatus" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$status" ] || [ "$status" = "None" ]; then
        skip "SageMaker notebook not found: $SAGEMAKER_NOTEBOOK"
        delete_service_role "$SAGEMAKER_ROLE"
        return
    fi

    # Stop first if running
    if [ "$status" = "InService" ]; then
        aws sagemaker stop-notebook-instance --notebook-instance-name "$SAGEMAKER_NOTEBOOK" --region "$REGION"
        info "Stopping SageMaker notebook (waiting)..."
        aws sagemaker wait notebook-instance-stopped --notebook-instance-name "$SAGEMAKER_NOTEBOOK" --region "$REGION" 2>/dev/null || sleep 60
    fi

    if [ "$status" = "Stopped" ] || [ "$status" = "InService" ]; then
        aws sagemaker delete-notebook-instance --notebook-instance-name "$SAGEMAKER_NOTEBOOK" --region "$REGION"
        success "Deleted SageMaker notebook: $SAGEMAKER_NOTEBOOK"
    fi

    delete_service_role "$SAGEMAKER_ROLE"
}

# Delete Transfer Family server
delete_transfer() {
    info "Deleting Transfer server: $TRANSFER_SERVER..."

    local server_id
    server_id=$(aws transfer list-servers --region "$REGION" \
        --query "Servers[?Tags[?Key=='Name' && Value=='$TRANSFER_SERVER']].ServerId | [0]" --output text 2>/dev/null) || true

    if [ -z "$server_id" ] || [ "$server_id" = "None" ] || [ "$server_id" = "null" ]; then
        skip "Transfer server not found: $TRANSFER_SERVER"
        return
    fi

    aws transfer delete-server --server-id "$server_id" --region "$REGION"
    success "Deleted Transfer server: $TRANSFER_SERVER ($server_id)"
}

# Delete FSx filesystem
delete_fsx() {
    info "Deleting FSx filesystem: $FSX_NAME..."

    local fs_id
    fs_id=$(aws fsx describe-file-systems --region "$REGION" \
        --query "FileSystems[?tags[?Key=='Name' && Value=='$FSX_NAME']].FileSystemId | [0]" --output text 2>/dev/null) || true

    if [ -z "$fs_id" ] || [ "$fs_id" = "None" ] || [ "$fs_id" = "null" ]; then
        skip "FSx filesystem not found: $FSX_NAME"
        return
    fi

    aws fsx delete-file-system --file-system-id "$fs_id" --region "$REGION" >/dev/null
    success "Initiated FSx deletion: $FSX_NAME ($fs_id)"
}

# Delete Network Firewall
delete_network_firewall() {
    info "Deleting Network Firewall: $NFW_FIREWALL..."

    if aws network-firewall describe-firewall --firewall-name "$NFW_FIREWALL" \
        --region "$REGION" >/dev/null 2>&1; then
        aws network-firewall delete-firewall --firewall-name "$NFW_FIREWALL" --region "$REGION" >/dev/null
        success "Initiated Network Firewall deletion: $NFW_FIREWALL"

        # Wait a bit for firewall to start deleting before removing policy
        info "Waiting for firewall to release policy..."
        sleep 30
    else
        skip "Network Firewall not found: $NFW_FIREWALL"
    fi

    # Delete firewall policy
    if aws network-firewall describe-firewall-policy --firewall-policy-name "$NFW_POLICY" \
        --region "$REGION" >/dev/null 2>&1; then
        aws network-firewall delete-firewall-policy --firewall-policy-name "$NFW_POLICY" \
            --region "$REGION" 2>/dev/null || warn "Firewall policy still in use, retry later"
    fi
}

# Delete DMS replication instance and subnet group
delete_dms() {
    info "Deleting DMS replication instance: $DMS_INSTANCE..."

    if aws dms describe-replication-instances --region "$REGION" \
        --filters "Name=replication-instance-id,Values=$DMS_INSTANCE" \
        --query "ReplicationInstances[0].ReplicationInstanceIdentifier" --output text 2>/dev/null | grep -q "$DMS_INSTANCE"; then
        aws dms delete-replication-instance \
            --replication-instance-arn "$(aws dms describe-replication-instances --region "$REGION" \
                --filters "Name=replication-instance-id,Values=$DMS_INSTANCE" \
                --query "ReplicationInstances[0].ReplicationInstanceArn" --output text)" \
            --region "$REGION" >/dev/null
        success "Initiated DMS deletion: $DMS_INSTANCE"
    else
        skip "DMS replication instance not found: $DMS_INSTANCE"
    fi

    # Delete subnet group (may need to wait)
    aws dms delete-replication-subnet-group \
        --replication-subnet-group-identifier "$DMS_SUBNET_GROUP" \
        --region "$REGION" 2>/dev/null || true
}

# Delete Amazon MQ broker
delete_mq() {
    info "Deleting MQ broker: $MQ_BROKER_NAME..."

    local broker_id
    broker_id=$(aws mq list-brokers --region "$REGION" \
        --query "BrokerSummaries[?BrokerName=='$MQ_BROKER_NAME'].BrokerId | [0]" --output text 2>/dev/null) || true

    if [ -z "$broker_id" ] || [ "$broker_id" = "None" ] || [ "$broker_id" = "null" ]; then
        skip "MQ broker not found: $MQ_BROKER_NAME"
        return
    fi

    aws mq delete-broker --broker-id "$broker_id" --region "$REGION" >/dev/null
    success "Initiated MQ broker deletion: $MQ_BROKER_NAME ($broker_id)"
}

# Delete DocumentDB cluster and instance
delete_docdb() {
    info "Deleting DocumentDB cluster: $DOCDB_CLUSTER..."

    # Delete instance first (use aws rds which supports --skip-final-snapshot)
    if aws docdb describe-db-instances --db-instance-identifier "$DOCDB_INSTANCE" \
        --region "$REGION" >/dev/null 2>&1; then
        aws rds delete-db-instance --db-instance-identifier "$DOCDB_INSTANCE" \
            --skip-final-snapshot --region "$REGION" >/dev/null 2>&1 || true
        success "Initiated DocumentDB instance deletion: $DOCDB_INSTANCE"
        info "Waiting for DocumentDB instance deletion..."
        aws rds wait db-instance-deleted --db-instance-identifier "$DOCDB_INSTANCE" --region "$REGION" 2>/dev/null || sleep 120
    fi

    # Delete cluster
    if aws docdb describe-db-clusters --db-cluster-identifier "$DOCDB_CLUSTER" \
        --region "$REGION" >/dev/null 2>&1; then
        aws rds delete-db-cluster --db-cluster-identifier "$DOCDB_CLUSTER" \
            --skip-final-snapshot --region "$REGION" >/dev/null 2>&1 || true
        success "Initiated DocumentDB cluster deletion: $DOCDB_CLUSTER"
    else
        skip "DocumentDB cluster not found: $DOCDB_CLUSTER"
    fi

    # Delete subnet group
    aws docdb delete-db-subnet-group --db-subnet-group-name "$DOCDB_SUBNET_GROUP" \
        --region "$REGION" 2>/dev/null || true
}

# Delete EMR cluster and roles
delete_emr() {
    info "Deleting EMR cluster: $EMR_CLUSTER_NAME..."

    local cluster_id
    cluster_id=$(aws emr list-clusters --active --region "$REGION" \
        --query "Clusters[?Name=='$EMR_CLUSTER_NAME'].Id | [0]" --output text 2>/dev/null) || true

    if [ -n "$cluster_id" ] && [ "$cluster_id" != "None" ] && [ "$cluster_id" != "null" ]; then
        aws emr terminate-clusters --cluster-ids "$cluster_id" --region "$REGION"
        success "Initiated EMR termination: $EMR_CLUSTER_NAME ($cluster_id)"
    else
        skip "EMR cluster not found (active): $EMR_CLUSTER_NAME"
    fi

    # Clean up instance profile
    if aws iam get-instance-profile --instance-profile-name "$EMR_INSTANCE_PROFILE" >/dev/null 2>&1; then
        aws iam remove-role-from-instance-profile \
            --instance-profile-name "$EMR_INSTANCE_PROFILE" \
            --role-name "$EMR_EC2_ROLE" 2>/dev/null || true
        aws iam delete-instance-profile --instance-profile-name "$EMR_INSTANCE_PROFILE" 2>/dev/null || true
        success "Deleted EMR instance profile: $EMR_INSTANCE_PROFILE"
    fi

    delete_service_role "$EMR_EC2_ROLE"
    delete_service_role "$EMR_ROLE"
}

# Delete Redshift Serverless
delete_redshift_serverless() {
    info "Deleting Redshift Serverless: $REDSHIFT_SL_WORKGROUP..."

    # Delete workgroup first
    local wg_status
    wg_status=$(aws redshift-serverless get-workgroup --workgroup-name "$REDSHIFT_SL_WORKGROUP" \
        --query "workgroup.status" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$wg_status" ] && [ "$wg_status" != "None" ]; then
        aws redshift-serverless delete-workgroup --workgroup-name "$REDSHIFT_SL_WORKGROUP" --region "$REGION" >/dev/null
        success "Initiated Redshift Serverless workgroup deletion: $REDSHIFT_SL_WORKGROUP"
        info "Waiting for workgroup deletion..."
        sleep 60
    else
        skip "Redshift Serverless workgroup not found: $REDSHIFT_SL_WORKGROUP"
    fi

    # Delete namespace
    local ns_status
    ns_status=$(aws redshift-serverless get-namespace --namespace-name "$REDSHIFT_SL_NAMESPACE" \
        --query "namespace.status" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$ns_status" ] && [ "$ns_status" != "None" ]; then
        aws redshift-serverless delete-namespace --namespace-name "$REDSHIFT_SL_NAMESPACE" --region "$REGION" >/dev/null
        success "Initiated Redshift Serverless namespace deletion: $REDSHIFT_SL_NAMESPACE"
    else
        skip "Redshift Serverless namespace not found: $REDSHIFT_SL_NAMESPACE"
    fi
}

# Delete Redshift cluster and subnet group
delete_redshift() {
    info "Deleting Redshift cluster: $REDSHIFT_CLUSTER..."

    if aws redshift describe-clusters --cluster-identifier "$REDSHIFT_CLUSTER" \
        --region "$REGION" >/dev/null 2>&1; then
        aws redshift delete-cluster --cluster-identifier "$REDSHIFT_CLUSTER" \
            --skip-final-cluster-snapshot --region "$REGION" >/dev/null
        success "Initiated Redshift cluster deletion: $REDSHIFT_CLUSTER"
    else
        skip "Redshift cluster not found: $REDSHIFT_CLUSTER"
    fi

    # Delete subnet group (may need to wait for cluster)
    aws redshift delete-cluster-subnet-group --cluster-subnet-group-name "$REDSHIFT_SUBNET_GROUP" \
        --region "$REGION" 2>/dev/null || true
}

# Delete OpenSearch domain
delete_opensearch() {
    info "Deleting OpenSearch domain: $OPENSEARCH_DOMAIN..."

    if aws opensearch describe-domain --domain-name "$OPENSEARCH_DOMAIN" \
        --region "$REGION" >/dev/null 2>&1; then
        aws opensearch delete-domain --domain-name "$OPENSEARCH_DOMAIN" --region "$REGION" >/dev/null
        success "Initiated OpenSearch domain deletion: $OPENSEARCH_DOMAIN"
    else
        skip "OpenSearch domain not found: $OPENSEARCH_DOMAIN"
    fi
}

# Delete Neptune cluster, instance, and subnet group
delete_neptune() {
    info "Deleting Neptune cluster: $NEPTUNE_CLUSTER..."

    # Delete instance first (use aws rds which supports --skip-final-snapshot)
    if aws neptune describe-db-instances --db-instance-identifier "$NEPTUNE_INSTANCE" \
        --region "$REGION" >/dev/null 2>&1; then
        aws rds delete-db-instance --db-instance-identifier "$NEPTUNE_INSTANCE" \
            --skip-final-snapshot --region "$REGION" >/dev/null 2>&1 || true
        success "Initiated Neptune instance deletion: $NEPTUNE_INSTANCE"
        info "Waiting for Neptune instance deletion..."
        aws rds wait db-instance-deleted --db-instance-identifier "$NEPTUNE_INSTANCE" --region "$REGION" 2>/dev/null || sleep 120
    fi

    # Delete cluster (use aws rds for consistent --skip-final-snapshot support)
    if aws neptune describe-db-clusters --db-cluster-identifier "$NEPTUNE_CLUSTER" \
        --region "$REGION" >/dev/null 2>&1; then
        aws rds delete-db-cluster --db-cluster-identifier "$NEPTUNE_CLUSTER" \
            --skip-final-snapshot --region "$REGION" >/dev/null 2>&1 || true
        success "Initiated Neptune cluster deletion: $NEPTUNE_CLUSTER"
    else
        skip "Neptune cluster not found: $NEPTUNE_CLUSTER"
    fi

    # Delete subnet group
    aws neptune delete-db-subnet-group --db-subnet-group-name "$NEPTUNE_SUBNET_GROUP" \
        --region "$REGION" 2>/dev/null || true
}

# Delete MSK cluster
delete_msk() {
    info "Deleting MSK cluster: $MSK_CLUSTER_NAME..."

    local cluster_arn
    cluster_arn=$(aws kafka list-clusters-v2 --region "$REGION" \
        --query "ClusterInfoList[?ClusterName=='$MSK_CLUSTER_NAME'].ClusterArn | [0]" --output text 2>/dev/null) || true

    if [ -z "$cluster_arn" ] || [ "$cluster_arn" = "None" ] || [ "$cluster_arn" = "null" ]; then
        skip "MSK cluster not found: $MSK_CLUSTER_NAME"
        return
    fi

    aws kafka delete-cluster --cluster-arn "$cluster_arn" --region "$REGION" >/dev/null
    success "Initiated MSK cluster deletion: $MSK_CLUSTER_NAME"
}

# Delete EKS cluster and role
delete_eks() {
    info "Deleting EKS cluster: $EKS_CLUSTER_NAME..."

    if aws eks describe-cluster --name "$EKS_CLUSTER_NAME" --region "$REGION" >/dev/null 2>&1; then
        aws eks delete-cluster --name "$EKS_CLUSTER_NAME" --region "$REGION" >/dev/null
        success "Initiated EKS cluster deletion: $EKS_CLUSTER_NAME"
    else
        skip "EKS cluster not found: $EKS_CLUSTER_NAME"
    fi

    delete_service_role "$EKS_ROLE"
}

# Delete shared DB subnet group
delete_db_subnet_group() {
    info "Deleting shared DB subnet group: $DB_SUBNET_GROUP..."

    if aws rds describe-db-subnet-groups --db-subnet-group-name "$DB_SUBNET_GROUP" \
        --region "$REGION" >/dev/null 2>&1; then
        aws rds delete-db-subnet-group --db-subnet-group-name "$DB_SUBNET_GROUP" \
            --region "$REGION" 2>/dev/null || warn "DB subnet group still in use, will be cleaned up later"
    else
        skip "DB subnet group not found: $DB_SUBNET_GROUP"
    fi
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
    echo "    - SNS topic: $SNS_TOPIC_NAME"
    echo "    - SQS queue: $SQS_QUEUE_NAME"
    echo "    - EFS filesystem: $EFS_NAME"
    echo "    - Backup vault: $BACKUP_VAULT_NAME"
    echo "    - VPC flow logs (+ log group + IAM role)"
    echo "    - S3 bucket: $S3_BUCKET"
    echo "    - ASG: $ASG_NAME"
    echo "    - EC2 instance: $EC2_INSTANCE_NAME"
    echo "    - EBS snapshot + volume: $EBS_VOLUME_NAME"
    echo "    - Launch Template: $LAUNCH_TEMPLATE_NAME"
    echo "    - VPC S3 gateway endpoint"
    echo "    - ECS cluster + task defs: $ECS_CLUSTER_NAME"
    echo "    - CloudFront distribution"
    echo "    - API Gateway REST: $APIGATEWAY_REST_NAME"
    echo "    - API Gateway V2: $APIGATEWAY_V2_NAME"
    echo "    - CodeBuild: $CODEBUILD_PROJECT (+ role: $CODEBUILD_ROLE)"
    echo "    - Kinesis: $KINESIS_STREAM"
    echo "    - Cognito: $COGNITO_POOL_NAME"
    echo "    - ACM certificate"
    echo "    - Glue job: $GLUE_JOB_NAME (+ role: $GLUE_ROLE)"
    echo "    - Step Functions: $SFN_STATE_MACHINE (+ role: $SFN_ROLE)"
    echo "    - Route53 zone: $ROUTE53_ZONE_NAME"
    echo "    - AppSync: $APPSYNC_API_NAME"
    echo "    - Athena: $ATHENA_WORKGROUP"
    echo ""
    echo "  Expensive resources:"
    echo "    - EKS: $EKS_CLUSTER_NAME (+ role: $EKS_ROLE)"
    echo "    - MSK: $MSK_CLUSTER_NAME"
    echo "    - Neptune: $NEPTUNE_CLUSTER (+ instance + subnet group)"
    echo "    - OpenSearch: $OPENSEARCH_DOMAIN"
    echo "    - Redshift: $REDSHIFT_CLUSTER (+ subnet group)"
    echo "    - Redshift Serverless: $REDSHIFT_SL_NAMESPACE/$REDSHIFT_SL_WORKGROUP"
    echo "    - EMR: $EMR_CLUSTER_NAME (+ roles + instance profile)"
    echo "    - DocumentDB: $DOCDB_CLUSTER (+ instance + subnet group)"
    echo "    - Amazon MQ: $MQ_BROKER_NAME"
    echo "    - DMS: $DMS_INSTANCE (+ subnet group)"
    echo "    - Network Firewall: $NFW_FIREWALL (+ policy)"
    echo "    - FSx: $FSX_NAME"
    echo "    - Transfer: $TRANSFER_SERVER"
    echo "    - SageMaker: $SAGEMAKER_NOTEBOOK (+ role)"
    echo "    - DAX: $DAX_CLUSTER (+ subnet group + role)"
    echo "    - Elastic Beanstalk: $EB_APP_NAME/$EB_ENV_NAME"
    echo "    - DataSync: $DATASYNC_TASK_NAME"
    echo "    - Shared DB subnet group: $DB_SUBNET_GROUP"
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

    # Delete new resources first (reverse dependency order)
    delete_asg
    delete_ec2_instance
    delete_ebs_snapshot
    delete_ebs_volume
    delete_launch_template
    delete_vpc_endpoint
    delete_ecs
    delete_cloudfront
    delete_apigateway_rest
    delete_apigateway_v2
    delete_codebuild
    delete_kinesis
    delete_cognito
    delete_acm
    delete_glue
    delete_stepfunctions
    delete_route53
    delete_appsync
    delete_athena

    # Delete expensive services (reverse order)
    delete_datasync
    delete_elasticbeanstalk
    delete_dax
    delete_sagemaker
    delete_transfer
    delete_fsx
    delete_network_firewall
    delete_dms
    delete_mq
    delete_docdb
    delete_emr
    delete_redshift_serverless
    delete_redshift
    delete_opensearch
    delete_neptune
    delete_msk
    delete_eks
    delete_db_subnet_group

    # Delete original resources
    delete_rds
    delete_cloudtrail
    delete_s3_bucket "$CLOUDTRAIL_BUCKET"
    delete_cloudwatch
    delete_ecr
    delete_kms
    delete_dynamodb
    delete_lambda
    delete_secrets_manager
    delete_sns
    delete_sqs
    delete_efs
    delete_backup_vault
    delete_vpc_flow_logs
    delete_s3_bucket "$S3_BUCKET"
    wait_for_rds_deletion
    print_summary
}

main "$@"
