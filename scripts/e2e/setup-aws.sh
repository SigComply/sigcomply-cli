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
POSITIVE_POLICY_NAMES=(
    "sigcomply-e2e-positive-policy-core"
    "sigcomply-e2e-positive-policy-extended"
    "sigcomply-e2e-positive-policy-provisioning"
    "sigcomply-e2e-positive-policy-provisioning-2"
    "sigcomply-e2e-positive-policy-provisioning-3"
    "sigcomply-e2e-positive-policy-provisioning-4"
)
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
ALB_NAME="sigcomply-e2e-test"
ALB_TG_NAME="sigcomply-e2e-tg"
ALB_SG_NAME="sigcomply-e2e-alb-sg"
SNS_TOPIC_NAME="sigcomply-e2e-test"
SQS_QUEUE_NAME="sigcomply-e2e-test"
EFS_NAME="sigcomply-e2e-test"
BACKUP_VAULT_NAME="sigcomply-e2e-test"

# New resources (Group 1: EC2)
LAUNCH_TEMPLATE_NAME="sigcomply-e2e-test"
EC2_INSTANCE_NAME="sigcomply-e2e-test"
EBS_VOLUME_NAME="sigcomply-e2e-test"
VPC_ENDPOINT_NAME="sigcomply-e2e-s3-endpoint"

# New resources (Group 2: Container & Compute)
ECS_CLUSTER_NAME="sigcomply-e2e-test"
ECS_TASK_FAMILY="sigcomply-e2e-test"
ASG_NAME="sigcomply-e2e-test"

# New resources (Group 3: Networking & CDN)
CLOUDFRONT_COMMENT="sigcomply-e2e-test"
APIGATEWAY_REST_NAME="sigcomply-e2e-test"
APIGATEWAY_V2_NAME="sigcomply-e2e-test"
ROUTE53_ZONE_NAME="sigcomply-e2e-test.internal"

# New resources (Group 4: Application Services)
CODEBUILD_PROJECT="sigcomply-e2e-test"
CODEBUILD_ROLE="sigcomply-e2e-codebuild-role"
KINESIS_STREAM="sigcomply-e2e-test"
COGNITO_POOL_NAME="sigcomply-e2e-test"
SFN_STATE_MACHINE="sigcomply-e2e-test"
SFN_ROLE="sigcomply-e2e-sfn-role"
APPSYNC_API_NAME="sigcomply-e2e-test"

# New resources (Group 5: Analytics & Security)
ATHENA_WORKGROUP="sigcomply-e2e-test"
ACM_CERT_NAME="sigcomply-e2e-test"
GLUE_JOB_NAME="sigcomply-e2e-test"
GLUE_ROLE="sigcomply-e2e-glue-role"

# Expensive resources (spin up/down per test run)
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
DMS_ROLE="sigcomply-e2e-dms-vpc-role"
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
    require_cmd openssl

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

# Helper: create or update a managed IAM policy
upsert_policy() {
    local policy_name="$1"
    local policy_document="$2"
    local policy_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/${policy_name}"

    if aws iam get-policy --policy-arn "$policy_arn" >/dev/null 2>&1; then
        local versions
        versions=$(aws iam list-policy-versions --policy-arn "$policy_arn" --query "Versions[?!IsDefaultVersion].VersionId" --output text)
        local version_count
        version_count=$(echo "$versions" | wc -w | tr -d ' ')
        if [ "$version_count" -ge 4 ]; then
            local oldest
            oldest=$(echo "$versions" | awk '{print $NF}')
            aws iam delete-policy-version --policy-arn "$policy_arn" --version-id "$oldest"
        fi
        aws iam create-policy-version \
            --policy-arn "$policy_arn" \
            --policy-document "$policy_document" \
            --set-as-default >/dev/null
        success "Updated IAM policy: $policy_name"
    else
        aws iam create-policy \
            --policy-name "$policy_name" \
            --policy-document "$policy_document" >/dev/null
        success "Created IAM policy: $policy_name"
    fi
}

# Create IAM policies
create_iam_policies() {
    info "Creating/updating IAM policies..."

    # --- Positive policy 1: Core services (original collectors) ---
    local positive_core
    positive_core=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "IAMReadAccess",
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary", "iam:GetAccountPasswordPolicy",
                "iam:ListUsers", "iam:GetUser", "iam:ListMFADevices",
                "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
                "iam:ListUserPolicies", "iam:ListAttachedUserPolicies",
                "iam:GetLoginProfile", "iam:ListGroupsForUser",
                "iam:GetAccountAuthorizationDetails",
                "iam:GenerateCredentialReport", "iam:GetCredentialReport",
                "iam:ListRoles", "iam:ListAttachedRolePolicies",
                "iam:ListPolicies", "iam:GetPolicyVersion",
                "iam:ListServerCertificates"
            ],
            "Resource": "*"
        },
        {
            "Sid": "S3ReadAccess",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets", "s3:GetBucketLocation",
                "s3:GetBucketPolicy", "s3:GetBucketPolicyStatus",
                "s3:GetBucketAcl", "s3:GetBucketVersioning",
                "s3:GetBucketLogging", "s3:GetEncryptionConfiguration",
                "s3:GetBucketPublicAccessBlock", "s3:GetAccountPublicAccessBlock",
                "s3:GetBucketTagging", "s3:ListBucket",
                "s3:GetBucketLifecycleConfiguration", "s3:GetObjectLockConfiguration",
                "s3:GetBucketReplication", "s3:GetBucketNotificationConfiguration"
            ],
            "Resource": "*"
        },
        {
            "Sid": "S3EvidenceStorage",
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::sigcomply-e2e-tests", "arn:aws:s3:::sigcomply-e2e-tests/*"]
        },
        {
            "Sid": "CloudTrailReadAccess",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors", "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudWatchLogsReadAccess",
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups", "logs:DescribeLogStreams",
                "logs:GetLogEvents", "logs:DescribeMetricFilters"
            ],
            "Resource": "*"
        },
        {
            "Sid": "KMSReadAccess",
            "Effect": "Allow",
            "Action": [
                "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy",
                "kms:GetKeyRotationStatus", "kms:ListAliases"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ECRReadAccess",
            "Effect": "Allow",
            "Action": [
                "ecr:DescribeRepositories", "ecr:GetRepositoryPolicy",
                "ecr:DescribeImages", "ecr:ListImages",
                "ecr:GetLifecyclePolicy", "ecr:DescribeImageScanFindings"
            ],
            "Resource": "*"
        },
        {
            "Sid": "RDSReadAccess",
            "Effect": "Allow",
            "Action": [
                "rds:DescribeDBInstances", "rds:DescribeDBClusters",
                "rds:DescribeDBSnapshots", "rds:DescribeDBSubnetGroups",
                "rds:ListTagsForResource", "rds:DescribeEventSubscriptions",
                "rds:DescribeDBParameterGroups", "rds:DescribeDBParameters",
                "rds:DescribeDBClusterSnapshots"
            ],
            "Resource": "*"
        },
        {
            "Sid": "MonitoringAndDataAccess",
            "Effect": "Allow",
            "Action": [
                "securityhub:DescribeHub", "securityhub:GetFindings", "securityhub:GetEnabledStandards",
                "cloudwatch:DescribeAlarms",
                "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
                "lambda:ListFunctions", "lambda:GetPolicy", "lambda:GetFunction",
                "dynamodb:ListTables", "dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups",
                "ecs:ListClusters", "ecs:DescribeClusters",
                "ecs:ListTaskDefinitionFamilies", "ecs:DescribeTaskDefinition",
                "eks:ListClusters", "eks:DescribeCluster",
                "acm:ListCertificates", "acm:DescribeCertificate",
                "cloudfront:ListDistributions", "cloudfront:GetDistribution",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTags",
                "wafv2:ListWebACLs", "wafv2:ListResourcesForWebACL", "wafv2:GetWebACL",
                "macie2:GetMacieSession",
                "ssm:DescribeInstanceInformation", "ssm:GetServiceSetting",
                "ssm:ListDocuments", "ssm:DescribeDocumentPermission",
                "guardduty:ListDetectors", "guardduty:GetDetector",
                "config:DescribeConfigurationRecorders",
                "config:DescribeConfigurationRecorderStatus",
                "config:DescribeConfigurationAggregators"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EC2ReadAccess",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs", "ec2:DescribeFlowLogs",
                "ec2:GetEbsDefaultKmsKeyId", "ec2:GetEbsEncryptionByDefault",
                "ec2:DescribeInstances", "ec2:DescribeSnapshots",
                "ec2:DescribeSubnets", "ec2:DescribeNetworkAcls",
                "ec2:DescribeLaunchTemplates", "ec2:DescribeLaunchTemplateVersions",
                "ec2:DescribeVpcEndpoints", "ec2:DescribeClientVpnEndpoints",
                "ec2:DescribeImages", "ec2:DescribeTransitGateways", "ec2:DescribeVolumes",
                "ec2:CreateFlowLogs", "ec2:DeleteFlowLogs"
            ],
            "Resource": "*"
        },
        {
            "Sid": "GovernanceAccess",
            "Effect": "Allow",
            "Action": [
                "es:ListDomainNames", "es:DescribeDomains",
                "backup:ListBackupPlans", "backup:GetBackupPlan",
                "backup:ListBackupVaults", "backup:DescribeBackupVault",
                "backup:ListRecoveryPointsByBackupVault",
                "access-analyzer:ListAnalyzers",
                "sso:ListInstances",
                "elasticache:DescribeReplicationGroups",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
)

    # --- Positive policy 2: Extended services (new collectors) ---
    local positive_extended
    positive_extended=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ComputeAndAnalyticsAccess",
            "Effect": "Allow",
            "Action": [
                "autoscaling:DescribeAutoScalingGroups", "autoscaling:DescribeLaunchConfigurations",
                "codebuild:ListProjects", "codebuild:BatchGetProjects",
                "elasticmapreduce:ListClusters", "elasticmapreduce:DescribeCluster",
                "elasticmapreduce:GetBlockPublicAccessConfiguration",
                "states:ListStateMachines", "states:DescribeStateMachine",
                "glue:GetJobs"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DatabaseAndStreamingAccess",
            "Effect": "Allow",
            "Action": [
                "dms:DescribeReplicationInstances", "dms:DescribeEndpoints", "dms:DescribeReplicationTasks",
                "kinesis:ListStreams", "kinesis:DescribeStreamSummary",
                "kafka:ListClustersV2",
                "neptune:DescribeDBClusters", "neptune:DescribeDBClusterSnapshots",
                "redshift-serverless:ListWorkgroups", "redshift-serverless:ListNamespaces",
                "redshift:DescribeClusters", "redshift:DescribeLoggingStatus",
                "redshift:DescribeClusterParameters",
                "dax:DescribeClusters"
            ],
            "Resource": "*"
        },
        {
            "Sid": "NetworkAndSecurityAccess",
            "Effect": "Allow",
            "Action": [
                "network-firewall:ListFirewalls", "network-firewall:DescribeFirewall",
                "network-firewall:DescribeLoggingConfiguration",
                "route53:ListHostedZones", "route53:ListQueryLoggingConfigs", "route53:GetDNSSEC",
                "transfer:ListServers", "transfer:DescribeServer",
                "inspector2:BatchGetAccountStatus",
                "events:ListRules", "events:ListTargetsByRule",
                "organizations:DescribeOrganization", "organizations:ListPolicies"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AIAndAppServicesAccess",
            "Effect": "Allow",
            "Action": [
                "sagemaker:ListNotebookInstances", "sagemaker:DescribeNotebookInstance",
                "appsync:ListGraphqlApis",
                "athena:ListWorkGroups", "athena:GetWorkGroup",
                "datasync:ListTasks", "datasync:DescribeTask",
                "bedrock:GetModelInvocationLoggingConfiguration",
                "apigateway:GET",
                "apigatewayv2:GetApis", "apigatewayv2:GetStages"
            ],
            "Resource": "*"
        },
        {
            "Sid": "StorageAndMessagingAccess",
            "Effect": "Allow",
            "Action": [
                "fsx:DescribeFileSystems",
                "mq:ListBrokers", "mq:DescribeBroker",
                "cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool",
                "elasticbeanstalk:DescribeEnvironments", "elasticbeanstalk:DescribeConfigurationSettings",
                "account:GetAlternateContact"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
)

    # --- Positive policy 3: Provisioning access (create/delete test resources) ---
    local positive_provisioning
    positive_provisioning=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SNSAccess",
            "Effect": "Allow",
            "Action": [
                "sns:ListTopics", "sns:GetTopicAttributes",
                "sns:ListSubscriptionsByTopic",
                "sns:CreateTopic", "sns:DeleteTopic"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SQSAccess",
            "Effect": "Allow",
            "Action": [
                "sqs:ListQueues", "sqs:GetQueueAttributes", "sqs:GetQueueUrl",
                "sqs:CreateQueue", "sqs:DeleteQueue"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EFSAccess",
            "Effect": "Allow",
            "Action": [
                "elasticfilesystem:DescribeFileSystems",
                "elasticfilesystem:DescribeFileSystemPolicy",
                "elasticfilesystem:DescribeBackupPolicy",
                "elasticfilesystem:CreateFileSystem",
                "elasticfilesystem:DeleteFileSystem"
            ],
            "Resource": "*"
        },
        {
            "Sid": "BackupProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "backup:CreateBackupVault", "backup:DeleteBackupVault"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EC2ProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "ec2:RunInstances", "ec2:TerminateInstances",
                "ec2:CreateLaunchTemplate", "ec2:DeleteLaunchTemplate",
                "ec2:CreateVolume", "ec2:DeleteVolume",
                "ec2:CreateSnapshot", "ec2:DeleteSnapshot",
                "ec2:CreateVpcEndpoint", "ec2:DeleteVpcEndpoints",
                "ec2:CreateTags"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ECSProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "ecs:CreateCluster", "ecs:DeleteCluster",
                "ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition",
                "ecs:ListTaskDefinitions"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudFrontProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "cloudfront:CreateDistribution", "cloudfront:DeleteDistribution",
                "cloudfront:UpdateDistribution", "cloudfront:GetDistributionConfig",
                "cloudfront:GetDistribution", "cloudfront:TagResource"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
)

    # --- Positive policy 4: Provisioning access part 2 (remaining services) ---
    local positive_provisioning_2
    positive_provisioning_2=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "APIGatewayProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "apigateway:POST", "apigateway:DELETE", "apigateway:PUT", "apigateway:PATCH",
                "apigatewayv2:CreateApi", "apigatewayv2:DeleteApi",
                "apigatewayv2:CreateStage", "apigatewayv2:DeleteStage"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CodeBuildProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "codebuild:CreateProject", "codebuild:DeleteProject"
            ],
            "Resource": "*"
        },
        {
            "Sid": "KinesisProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "kinesis:CreateStream", "kinesis:DeleteStream"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CognitoProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "cognito-idp:CreateUserPool", "cognito-idp:DeleteUserPool"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ACMProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "acm:ImportCertificate", "acm:DeleteCertificate",
                "acm:AddTagsToCertificate"
            ],
            "Resource": "*"
        },
        {
            "Sid": "GlueProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "glue:CreateJob", "glue:DeleteJob"
            ],
            "Resource": "*"
        },
        {
            "Sid": "StepFunctionsProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "states:CreateStateMachine", "states:DeleteStateMachine"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Route53ProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "route53:CreateHostedZone", "route53:DeleteHostedZone",
                "route53:ListResourceRecordSets", "route53:ChangeResourceRecordSets"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AppSyncProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "appsync:CreateGraphqlApi", "appsync:DeleteGraphqlApi"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AthenaProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "athena:CreateWorkGroup", "athena:DeleteWorkGroup"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AutoScalingProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "autoscaling:CreateAutoScalingGroup", "autoscaling:DeleteAutoScalingGroup",
                "autoscaling:UpdateAutoScalingGroup"
            ],
            "Resource": "*"
        },
        {
            "Sid": "IAMRoleProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole", "iam:DeleteRole",
                "iam:AttachRolePolicy", "iam:DetachRolePolicy",
                "iam:PutRolePolicy", "iam:DeleteRolePolicy",
                "iam:PassRole", "iam:GetRole",
                "iam:ListAttachedRolePolicies", "iam:ListRolePolicies"
            ],
            "Resource": [
                "arn:aws:iam::*:role/sigcomply-e2e-*",
                "arn:aws:iam::*:instance-profile/sigcomply-e2e-*"
            ]
        },
        {
            "Sid": "IAMInstanceProfileAccess",
            "Effect": "Allow",
            "Action": [
                "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile",
                "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile",
                "iam:GetInstanceProfile"
            ],
            "Resource": "arn:aws:iam::*:instance-profile/sigcomply-e2e-*"
        }
    ]
}
POLICY
)

    # --- Positive policy 5: Provisioning access part 3 (expensive services group 1) ---
    local positive_provisioning_3
    positive_provisioning_3=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EKSProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "eks:CreateCluster", "eks:DeleteCluster", "eks:TagResource"
            ],
            "Resource": "*"
        },
        {
            "Sid": "MSKProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "kafka:CreateClusterV2", "kafka:DeleteCluster", "kafka:TagResource"
            ],
            "Resource": "*"
        },
        {
            "Sid": "NeptuneProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "neptune:CreateDBCluster", "neptune:DeleteDBCluster",
                "neptune:CreateDBInstance", "neptune:DeleteDBInstance",
                "neptune:CreateDBSubnetGroup", "neptune:DeleteDBSubnetGroup"
            ],
            "Resource": "*"
        },
        {
            "Sid": "OpenSearchProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "es:CreateDomain", "es:DeleteDomain", "es:AddTags"
            ],
            "Resource": "*"
        },
        {
            "Sid": "RedshiftProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "redshift:CreateCluster", "redshift:DeleteCluster",
                "redshift:CreateClusterSubnetGroup", "redshift:DeleteClusterSubnetGroup",
                "redshift-serverless:CreateNamespace", "redshift-serverless:DeleteNamespace",
                "redshift-serverless:CreateWorkgroup", "redshift-serverless:DeleteWorkgroup"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EMRProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "elasticmapreduce:RunJobFlow", "elasticmapreduce:TerminateJobFlows",
                "elasticmapreduce:AddTags"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DocumentDBProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "rds:CreateDBCluster", "rds:DeleteDBCluster",
                "rds:CreateDBInstance", "rds:DeleteDBInstance",
                "rds:CreateDBSubnetGroup", "rds:DeleteDBSubnetGroup",
                "rds:AddTagsToResource"
            ],
            "Resource": "*"
        },
        {
            "Sid": "MQProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "mq:CreateBroker", "mq:DeleteBroker", "mq:CreateTags"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
)

    # --- Positive policy 6: Provisioning access part 4 (expensive services group 2) ---
    local positive_provisioning_4
    positive_provisioning_4=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DMSProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "dms:CreateReplicationInstance", "dms:DeleteReplicationInstance",
                "dms:CreateReplicationSubnetGroup", "dms:DeleteReplicationSubnetGroup",
                "dms:AddTagsToResource"
            ],
            "Resource": "*"
        },
        {
            "Sid": "NetworkFirewallProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "network-firewall:CreateFirewall", "network-firewall:DeleteFirewall",
                "network-firewall:CreateFirewallPolicy", "network-firewall:DeleteFirewallPolicy",
                "network-firewall:DescribeFirewall"
            ],
            "Resource": "*"
        },
        {
            "Sid": "FSxProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "fsx:CreateFileSystem", "fsx:DeleteFileSystem", "fsx:TagResource"
            ],
            "Resource": "*"
        },
        {
            "Sid": "TransferProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "transfer:CreateServer", "transfer:DeleteServer", "transfer:TagResource"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SageMakerProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "sagemaker:CreateNotebookInstance", "sagemaker:DeleteNotebookInstance",
                "sagemaker:StopNotebookInstance", "sagemaker:DescribeNotebookInstance",
                "sagemaker:AddTags"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DAXProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "dax:CreateCluster", "dax:DeleteCluster",
                "dax:CreateSubnetGroup", "dax:DeleteSubnetGroup"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ElasticBeanstalkProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "elasticbeanstalk:CreateApplication", "elasticbeanstalk:DeleteApplication",
                "elasticbeanstalk:CreateEnvironment", "elasticbeanstalk:TerminateEnvironment",
                "elasticbeanstalk:DescribeEnvironments", "elasticbeanstalk:CreateStorageLocation"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DataSyncProvisionAccess",
            "Effect": "Allow",
            "Action": [
                "datasync:CreateLocationS3", "datasync:DeleteLocation",
                "datasync:CreateTask", "datasync:DeleteTask"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SubnetGroupAndSecurityAccess",
            "Effect": "Allow",
            "Action": [
                "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
                "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
                "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets",
                "ec2:DescribeVpcs", "ec2:DescribeAvailabilityZones"
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
            "Action": ["sts:GetCallerIdentity"],
            "Resource": "*"
        }
    ]
}
POLICY
)

    # Create or update all positive policies and attach to positive user
    local policy_docs=("$positive_core" "$positive_extended" "$positive_provisioning" "$positive_provisioning_2" "$positive_provisioning_3" "$positive_provisioning_4")
    for i in "${!POSITIVE_POLICY_NAMES[@]}"; do
        local pname="${POSITIVE_POLICY_NAMES[$i]}"
        local pdoc="${policy_docs[$i]}"
        upsert_policy "$pname" "$pdoc"
        aws iam attach-user-policy \
            --user-name "sigcomply-e2e-positive" \
            --policy-arn "arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/${pname}" 2>/dev/null || true
        success "Attached $pname to sigcomply-e2e-positive"
    done

    # Clean up old single positive policy if it exists
    local old_policy_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/sigcomply-e2e-positive-policy"
    if aws iam get-policy --policy-arn "$old_policy_arn" >/dev/null 2>&1; then
        aws iam detach-user-policy \
            --user-name "sigcomply-e2e-positive" \
            --policy-arn "$old_policy_arn" 2>/dev/null || true
        # Delete all non-default versions first
        local old_versions
        old_versions=$(aws iam list-policy-versions --policy-arn "$old_policy_arn" \
            --query "Versions[?!IsDefaultVersion].VersionId" --output text 2>/dev/null) || true
        for ver in $old_versions; do
            aws iam delete-policy-version --policy-arn "$old_policy_arn" --version-id "$ver" 2>/dev/null || true
        done
        aws iam delete-policy --policy-arn "$old_policy_arn" 2>/dev/null || true
        success "Cleaned up old single positive policy"
    fi

    # Create or update negative policy
    upsert_policy "$NEGATIVE_POLICY_NAME" "$negative_policy"
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

    if aws s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
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

# Provision ELBv2 ALB (intentionally non-compliant: HTTP-only, no HTTPS)
provision_elbv2() {
    info "Provisioning ALB: $ALB_NAME..."

    # Check if ALB already exists
    local alb_arn
    alb_arn=$(aws elbv2 describe-load-balancers --names "$ALB_NAME" \
        --query "LoadBalancers[0].LoadBalancerArn" --output text 2>/dev/null) || true

    if [ -n "$alb_arn" ] && [ "$alb_arn" != "None" ]; then
        success "ALB already exists: $ALB_NAME"
        return
    fi

    # Get default VPC
    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    if [ -z "$vpc_id" ] || [ "$vpc_id" = "None" ]; then
        warn "No default VPC found in $REGION. Skipping ALB provisioning."
        return
    fi

    # Get at least 2 subnets from the default VPC (ALB requires 2 AZs)
    local subnet_ids
    subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
        --query "Subnets[?DefaultForAz==\`true\`].SubnetId | [:2]" --output text --region "$REGION")

    local subnet_count
    subnet_count=$(echo "$subnet_ids" | wc -w | tr -d ' ')
    if [ "$subnet_count" -lt 2 ]; then
        warn "Need at least 2 subnets for ALB, found $subnet_count. Skipping ALB provisioning."
        return
    fi

    # Create security group for ALB (if not exists)
    local sg_id
    sg_id=$(aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=$ALB_SG_NAME" "Name=vpc-id,Values=$vpc_id" \
        --query "SecurityGroups[0].GroupId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$sg_id" ] || [ "$sg_id" = "None" ]; then
        sg_id=$(aws ec2 create-security-group \
            --group-name "$ALB_SG_NAME" \
            --description "SigComply E2E ALB security group" \
            --vpc-id "$vpc_id" \
            --query "GroupId" --output text --region "$REGION")

        # Allow inbound HTTP (port 80) for testing
        aws ec2 authorize-security-group-ingress \
            --group-id "$sg_id" \
            --protocol tcp --port 80 --cidr 0.0.0.0/0 \
            --region "$REGION" >/dev/null 2>&1 || true

        success "Created security group: $ALB_SG_NAME ($sg_id)"
    else
        success "Security group already exists: $ALB_SG_NAME ($sg_id)"
    fi

    # Create target group (required for forward action)
    local tg_arn
    tg_arn=$(aws elbv2 describe-target-groups --names "$ALB_TG_NAME" \
        --query "TargetGroups[0].TargetGroupArn" --output text 2>/dev/null) || true

    if [ -z "$tg_arn" ] || [ "$tg_arn" = "None" ]; then
        tg_arn=$(aws elbv2 create-target-group \
            --name "$ALB_TG_NAME" \
            --protocol HTTP \
            --port 80 \
            --vpc-id "$vpc_id" \
            --target-type ip \
            --query "TargetGroups[0].TargetGroupArn" --output text --region "$REGION")
        success "Created target group: $ALB_TG_NAME"
    else
        success "Target group already exists: $ALB_TG_NAME"
    fi

    # Create ALB
    # shellcheck disable=SC2086
    alb_arn=$(aws elbv2 create-load-balancer \
        --name "$ALB_NAME" \
        --subnets $subnet_ids \
        --security-groups "$sg_id" \
        --scheme internet-facing \
        --type application \
        --query "LoadBalancers[0].LoadBalancerArn" --output text --region "$REGION")
    success "Created ALB: $ALB_NAME"

    # Create HTTP-only listener (intentionally non-compliant — no HTTPS)
    aws elbv2 create-listener \
        --load-balancer-arn "$alb_arn" \
        --protocol HTTP \
        --port 80 \
        --default-actions "Type=forward,TargetGroupArn=$tg_arn" \
        --region "$REGION" >/dev/null
    success "Created HTTP listener on port 80 (intentionally non-compliant — no HTTPS)"
}

# Provision SNS topic (intentionally non-compliant: no KMS encryption, no delivery logging)
provision_sns() {
    info "Provisioning SNS topic: $SNS_TOPIC_NAME..."

    local topic_arn
    topic_arn=$(aws sns list-topics --region "$REGION" --query "Topics[?ends_with(TopicArn, ':$SNS_TOPIC_NAME')].TopicArn | [0]" --output text 2>/dev/null) || true

    if [ -n "$topic_arn" ] && [ "$topic_arn" != "None" ] && [ "$topic_arn" != "null" ]; then
        success "SNS topic already exists: $SNS_TOPIC_NAME"
        return
    fi

    aws sns create-topic \
        --name "$SNS_TOPIC_NAME" \
        --region "$REGION" >/dev/null
    success "Created SNS topic: $SNS_TOPIC_NAME (no KMS encryption, no delivery logging — intentionally non-compliant)"
}

# Provision SQS queue (intentionally non-compliant: no encryption, no DLQ)
provision_sqs() {
    info "Provisioning SQS queue: $SQS_QUEUE_NAME..."

    local queue_url
    queue_url=$(aws sqs get-queue-url --queue-name "$SQS_QUEUE_NAME" --region "$REGION" --query "QueueUrl" --output text 2>/dev/null) || true

    if [ -n "$queue_url" ] && [ "$queue_url" != "None" ] && [ "$queue_url" != "null" ]; then
        success "SQS queue already exists: $SQS_QUEUE_NAME"
        return
    fi

    aws sqs create-queue \
        --queue-name "$SQS_QUEUE_NAME" \
        --region "$REGION" >/dev/null
    success "Created SQS queue: $SQS_QUEUE_NAME (no encryption, no DLQ — intentionally non-compliant)"
}

# Provision EFS filesystem (intentionally non-compliant: no backup configured)
provision_efs() {
    info "Provisioning EFS filesystem: $EFS_NAME..."

    local fs_id
    fs_id=$(aws efs describe-file-systems --region "$REGION" \
        --query "FileSystems[?Name=='$EFS_NAME'].FileSystemId | [0]" --output text 2>/dev/null) || true

    if [ -n "$fs_id" ] && [ "$fs_id" != "None" ] && [ "$fs_id" != "null" ]; then
        success "EFS filesystem already exists: $EFS_NAME (id: $fs_id)"
        return
    fi

    aws efs create-file-system \
        --performance-mode generalPurpose \
        --throughput-mode bursting \
        --tags "Key=Name,Value=$EFS_NAME" \
        --no-backup \
        --region "$REGION" >/dev/null
    success "Created EFS filesystem: $EFS_NAME (no backup — intentionally non-compliant)"
}

# Provision Backup vault (intentionally non-compliant: no vault lock, default encryption)
provision_backup_vault() {
    info "Provisioning Backup vault: $BACKUP_VAULT_NAME..."

    if aws backup describe-backup-vault --backup-vault-name "$BACKUP_VAULT_NAME" --region "$REGION" >/dev/null 2>&1; then
        success "Backup vault already exists: $BACKUP_VAULT_NAME"
        return
    fi

    aws backup create-backup-vault \
        --backup-vault-name "$BACKUP_VAULT_NAME" \
        --region "$REGION" >/dev/null
    success "Created Backup vault: $BACKUP_VAULT_NAME (no vault lock — intentionally non-compliant)"
}

# Provision VPC flow logs on default VPC
provision_vpc_flow_logs() {
    info "Provisioning VPC flow logs on default VPC..."

    # Get default VPC
    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    if [ -z "$vpc_id" ] || [ "$vpc_id" = "None" ]; then
        warn "No default VPC found in $REGION. Skipping VPC flow logs provisioning."
        return
    fi

    # Check if flow logs already exist for this VPC
    local existing_flow_logs
    existing_flow_logs=$(aws ec2 describe-flow-logs \
        --filter "Name=resource-id,Values=$vpc_id" \
        --query "FlowLogs[0].FlowLogId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$existing_flow_logs" ] && [ "$existing_flow_logs" != "None" ] && [ "$existing_flow_logs" != "null" ]; then
        success "VPC flow logs already exist for $vpc_id: $existing_flow_logs"
        return
    fi

    # Create flow logs to CloudWatch Logs
    local flow_log_group="sigcomply-e2e-vpc-flow-logs"

    # Create log group for flow logs if it doesn't exist
    if ! aws logs describe-log-groups --log-group-name-prefix "$flow_log_group" \
        --query "logGroups[?logGroupName=='$flow_log_group'].logGroupName" --output text 2>/dev/null | grep -q "$flow_log_group"; then
        aws logs create-log-group --log-group-name "$flow_log_group" --region "$REGION"
        success "Created CloudWatch log group for flow logs: $flow_log_group"
    fi

    # Create IAM role for flow logs (if not exists)
    local flow_log_role="sigcomply-e2e-flow-log-role"
    local role_arn
    role_arn=$(aws iam get-role --role-name "$flow_log_role" --query "Role.Arn" --output text 2>/dev/null) || true

    if [ -z "$role_arn" ] || [ "$role_arn" = "None" ]; then
        local assume_role_policy
        assume_role_policy=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "vpc-flow-logs.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
)
        role_arn=$(aws iam create-role \
            --role-name "$flow_log_role" \
            --assume-role-policy-document "$assume_role_policy" \
            --query "Role.Arn" --output text)

        # Attach policy for CloudWatch Logs access
        local log_policy
        log_policy=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
)
        aws iam put-role-policy \
            --role-name "$flow_log_role" \
            --policy-name "flow-log-cloudwatch-access" \
            --policy-document "$log_policy"

        success "Created flow log IAM role: $flow_log_role"
        info "Waiting for IAM role to propagate..."
        sleep 10
    else
        success "Flow log IAM role already exists: $flow_log_role"
    fi

    aws ec2 create-flow-logs \
        --resource-type VPC \
        --resource-ids "$vpc_id" \
        --traffic-type ALL \
        --log-destination-type cloud-watch-logs \
        --log-group-name "$flow_log_group" \
        --deliver-logs-permission-arn "$role_arn" \
        --region "$REGION" >/dev/null
    success "Created VPC flow logs for $vpc_id → $flow_log_group"
}

# Helper: create IAM service role if it doesn't exist
create_service_role() {
    local role_name="$1"
    local service="$2"
    local role_arn

    role_arn=$(aws iam get-role --role-name "$role_name" --query "Role.Arn" --output text 2>/dev/null) || true

    if [ -n "$role_arn" ] && [ "$role_arn" != "None" ]; then
        success "IAM role already exists: $role_name" >&2
        echo "$role_arn"
        return
    fi

    local assume_role_policy
    assume_role_policy=$(cat <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": "${service}" },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
)
    role_arn=$(aws iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$assume_role_policy" \
        --query "Role.Arn" --output text)
    success "Created IAM role: $role_name" >&2
    echo "$role_arn"
}

# Provision EC2 Launch Template (intentionally non-compliant: IMDSv1 allowed)
provision_launch_template() {
    info "Provisioning EC2 Launch Template: $LAUNCH_TEMPLATE_NAME..."

    if aws ec2 describe-launch-templates --launch-template-names "$LAUNCH_TEMPLATE_NAME" \
        --region "$REGION" >/dev/null 2>&1; then
        success "Launch Template already exists: $LAUNCH_TEMPLATE_NAME"
        return
    fi

    aws ec2 create-launch-template \
        --launch-template-name "$LAUNCH_TEMPLATE_NAME" \
        --launch-template-data '{
            "ImageId": "resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
            "InstanceType": "t3.micro",
            "MetadataOptions": {
                "HttpTokens": "optional",
                "HttpEndpoint": "enabled"
            },
            "NetworkInterfaces": [{
                "DeviceIndex": 0,
                "AssociatePublicIpAddress": true
            }]
        }' \
        --region "$REGION" >/dev/null
    success "Created Launch Template: $LAUNCH_TEMPLATE_NAME (IMDSv1 allowed — intentionally non-compliant)"
}

# Provision EC2 Instance (intentionally non-compliant: IMDSv1, public IP, no monitoring)
provision_ec2_instance() {
    info "Provisioning EC2 instance: $EC2_INSTANCE_NAME..."

    # Check if instance already exists (by Name tag, running/pending state)
    local instance_id
    instance_id=$(aws ec2 describe-instances \
        --filters "Name=tag:Name,Values=$EC2_INSTANCE_NAME" "Name=instance-state-name,Values=running,pending,stopped" \
        --query "Reservations[0].Instances[0].InstanceId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$instance_id" ] && [ "$instance_id" != "None" ]; then
        success "EC2 instance already exists: $EC2_INSTANCE_NAME ($instance_id)"
        return
    fi

    instance_id=$(aws ec2 run-instances \
        --launch-template "LaunchTemplateName=$LAUNCH_TEMPLATE_NAME" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$EC2_INSTANCE_NAME}]" \
        --query "Instances[0].InstanceId" --output text --region "$REGION")
    success "Created EC2 instance: $EC2_INSTANCE_NAME ($instance_id) — intentionally non-compliant"
}

# Provision EBS Volume (intentionally non-compliant: not encrypted)
provision_ebs_volume() {
    info "Provisioning EBS volume: $EBS_VOLUME_NAME..."

    local volume_id
    volume_id=$(aws ec2 describe-volumes \
        --filters "Name=tag:Name,Values=$EBS_VOLUME_NAME" "Name=status,Values=available,in-use" \
        --query "Volumes[0].VolumeId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$volume_id" ] && [ "$volume_id" != "None" ]; then
        success "EBS volume already exists: $EBS_VOLUME_NAME ($volume_id)"
        return
    fi

    # Get first AZ in the region
    local az
    az=$(aws ec2 describe-availability-zones --region "$REGION" \
        --query "AvailabilityZones[0].ZoneName" --output text)

    volume_id=$(aws ec2 create-volume \
        --volume-type gp3 \
        --size 1 \
        --availability-zone "$az" \
        --no-encrypted \
        --tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=$EBS_VOLUME_NAME}]" \
        --query "VolumeId" --output text --region "$REGION")
    success "Created EBS volume: $EBS_VOLUME_NAME ($volume_id) — unencrypted, intentionally non-compliant"
}

# Provision EBS Snapshot (intentionally non-compliant: unencrypted)
provision_ebs_snapshot() {
    info "Provisioning EBS snapshot..."

    # Check if snapshot already exists
    local snapshot_id
    snapshot_id=$(aws ec2 describe-snapshots --owner-ids self \
        --filters "Name=tag:Name,Values=$EBS_VOLUME_NAME-snapshot" \
        --query "Snapshots[0].SnapshotId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$snapshot_id" ] && [ "$snapshot_id" != "None" ]; then
        success "EBS snapshot already exists: $snapshot_id"
        return
    fi

    # Get the volume ID
    local volume_id
    volume_id=$(aws ec2 describe-volumes \
        --filters "Name=tag:Name,Values=$EBS_VOLUME_NAME" "Name=status,Values=available,in-use" \
        --query "Volumes[0].VolumeId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$volume_id" ] || [ "$volume_id" = "None" ]; then
        warn "EBS volume not found for snapshot. Skipping."
        return
    fi

    snapshot_id=$(aws ec2 create-snapshot \
        --volume-id "$volume_id" \
        --description "SigComply E2E test snapshot" \
        --tag-specifications "ResourceType=snapshot,Tags=[{Key=Name,Value=$EBS_VOLUME_NAME-snapshot}]" \
        --query "SnapshotId" --output text --region "$REGION")
    success "Created EBS snapshot: $snapshot_id — unencrypted, intentionally non-compliant"
}

# Provision VPC Endpoint (S3 gateway — compliant resource)
provision_vpc_endpoint() {
    info "Provisioning VPC endpoint for S3..."

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    if [ -z "$vpc_id" ] || [ "$vpc_id" = "None" ]; then
        warn "No default VPC found. Skipping VPC endpoint."
        return
    fi

    # Check if S3 gateway endpoint already exists
    local endpoint_id
    endpoint_id=$(aws ec2 describe-vpc-endpoints \
        --filters "Name=vpc-id,Values=$vpc_id" "Name=service-name,Values=com.amazonaws.$REGION.s3" "Name=vpc-endpoint-type,Values=Gateway" \
        --query "VpcEndpoints[0].VpcEndpointId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$endpoint_id" ] && [ "$endpoint_id" != "None" ]; then
        success "VPC S3 gateway endpoint already exists: $endpoint_id"
        return
    fi

    # Get route table for default VPC
    local rtb_id
    rtb_id=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpc_id" "Name=association.main,Values=true" \
        --query "RouteTables[0].RouteTableId" --output text --region "$REGION")

    endpoint_id=$(aws ec2 create-vpc-endpoint \
        --vpc-id "$vpc_id" \
        --service-name "com.amazonaws.$REGION.s3" \
        --route-table-ids "$rtb_id" \
        --vpc-endpoint-type Gateway \
        --query "VpcEndpoint.VpcEndpointId" --output text --region "$REGION")
    success "Created VPC S3 gateway endpoint: $endpoint_id"
}

# Provision ECS Cluster + Task Definition (intentionally non-compliant)
provision_ecs() {
    info "Provisioning ECS cluster: $ECS_CLUSTER_NAME..."

    # Create cluster (no container insights — non-compliant)
    if aws ecs describe-clusters --clusters "$ECS_CLUSTER_NAME" --region "$REGION" \
        --query "clusters[?status=='ACTIVE'].clusterName" --output text 2>/dev/null | grep -q "$ECS_CLUSTER_NAME"; then
        success "ECS cluster already exists: $ECS_CLUSTER_NAME"
    else
        aws ecs create-cluster --cluster-name "$ECS_CLUSTER_NAME" --region "$REGION" >/dev/null
        success "Created ECS cluster: $ECS_CLUSTER_NAME (no container insights — intentionally non-compliant)"
    fi

    # Register task definition (privileged, root, no logging — non-compliant)
    info "Registering ECS task definition: $ECS_TASK_FAMILY..."
    aws ecs register-task-definition \
        --family "$ECS_TASK_FAMILY" \
        --requires-compatibilities EC2 \
        --network-mode bridge \
        --container-definitions '[{
            "name": "sigcomply-e2e-test",
            "image": "alpine:latest",
            "essential": true,
            "memory": 128,
            "privileged": true,
            "user": "root",
            "readonlyRootFilesystem": false
        }]' \
        --region "$REGION" >/dev/null
    success "Registered ECS task definition: $ECS_TASK_FAMILY (privileged, root, no logging — intentionally non-compliant)"
}

# Provision Auto Scaling Group (intentionally non-compliant: EC2 health check, single AZ)
provision_asg() {
    info "Provisioning Auto Scaling Group: $ASG_NAME..."

    if aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$ASG_NAME" \
        --query "AutoScalingGroups[0].AutoScalingGroupName" --output text --region "$REGION" 2>/dev/null | grep -q "$ASG_NAME"; then
        success "ASG already exists: $ASG_NAME"
        return
    fi

    # Get first subnet from default VPC
    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    local subnet_id
    subnet_id=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
        --query "Subnets[?DefaultForAz==\`true\`].SubnetId | [0]" --output text --region "$REGION")

    # Get launch template ID
    local lt_id
    lt_id=$(aws ec2 describe-launch-templates --launch-template-names "$LAUNCH_TEMPLATE_NAME" \
        --query "LaunchTemplates[0].LaunchTemplateId" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$lt_id" ] || [ "$lt_id" = "None" ]; then
        warn "Launch template not found. Skipping ASG."
        return
    fi

    aws autoscaling create-auto-scaling-group \
        --auto-scaling-group-name "$ASG_NAME" \
        --launch-template "LaunchTemplateId=$lt_id,Version=\$Latest" \
        --min-size 0 --max-size 0 --desired-capacity 0 \
        --vpc-zone-identifier "$subnet_id" \
        --health-check-type EC2 \
        --region "$REGION"
    success "Created ASG: $ASG_NAME (desired=0, EC2 health check, single AZ — intentionally non-compliant)"
}

# Provision CloudFront Distribution (intentionally non-compliant: allow-all protocol, no WAF, no logging)
provision_cloudfront() {
    info "Provisioning CloudFront distribution..."

    # Check if distribution with our comment already exists
    local dist_id
    dist_id=$(aws cloudfront list-distributions \
        --query "DistributionList.Items[?Comment=='$CLOUDFRONT_COMMENT'].Id | [0]" --output text 2>/dev/null) || true

    if [ -n "$dist_id" ] && [ "$dist_id" != "None" ] && [ "$dist_id" != "null" ]; then
        success "CloudFront distribution already exists: $dist_id"
        return
    fi

    local dist_config
    dist_config=$(cat <<'DISTCFG'
{
    "CallerReference": "sigcomply-e2e-TIMESTAMP",
    "Comment": "sigcomply-e2e-test",
    "Enabled": true,
    "Origins": {
        "Quantity": 1,
        "Items": [
            {
                "Id": "sigcomply-e2e-origin",
                "DomainName": "sigcomply-e2e-tests.s3.amazonaws.com",
                "S3OriginConfig": {
                    "OriginAccessIdentity": ""
                }
            }
        ]
    },
    "DefaultCacheBehavior": {
        "TargetOriginId": "sigcomply-e2e-origin",
        "ViewerProtocolPolicy": "allow-all",
        "AllowedMethods": {
            "Quantity": 2,
            "Items": ["HEAD", "GET"],
            "CachedMethods": {
                "Quantity": 2,
                "Items": ["HEAD", "GET"]
            }
        },
        "ForwardedValues": {
            "QueryString": false,
            "Cookies": { "Forward": "none" }
        },
        "MinTTL": 0,
        "DefaultTTL": 86400,
        "MaxTTL": 31536000,
        "Compress": false
    }
}
DISTCFG
)
    # Replace timestamp for unique caller reference
    dist_config=$(echo "$dist_config" | sed "s/TIMESTAMP/$(date +%s)/")

    dist_id=$(aws cloudfront create-distribution \
        --distribution-config "$dist_config" \
        --query "Distribution.Id" --output text)
    success "Created CloudFront distribution: $dist_id (allow-all, no WAF, no logging — intentionally non-compliant)"
}

# Provision API Gateway REST API (intentionally non-compliant: no authorizer, no WAF, no logging)
provision_apigateway_rest() {
    info "Provisioning API Gateway REST API: $APIGATEWAY_REST_NAME..."

    local api_id
    api_id=$(aws apigateway get-rest-apis \
        --query "items[?name=='$APIGATEWAY_REST_NAME'].id | [0]" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$api_id" ] && [ "$api_id" != "None" ] && [ "$api_id" != "null" ]; then
        success "API Gateway REST API already exists: $APIGATEWAY_REST_NAME ($api_id)"
        return
    fi

    api_id=$(aws apigateway create-rest-api \
        --name "$APIGATEWAY_REST_NAME" \
        --description "SigComply E2E test REST API" \
        --endpoint-configuration "types=REGIONAL" \
        --query "id" --output text --region "$REGION")

    # Create a deployment + stage so it shows up in policy checks
    local root_id
    root_id=$(aws apigateway get-resources --rest-api-id "$api_id" \
        --query "items[?path=='/'].id" --output text --region "$REGION")

    aws apigateway put-method \
        --rest-api-id "$api_id" \
        --resource-id "$root_id" \
        --http-method GET \
        --authorization-type NONE \
        --region "$REGION" >/dev/null

    aws apigateway put-integration \
        --rest-api-id "$api_id" \
        --resource-id "$root_id" \
        --http-method GET \
        --type MOCK \
        --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
        --region "$REGION" >/dev/null

    aws apigateway create-deployment \
        --rest-api-id "$api_id" \
        --stage-name "e2e" \
        --region "$REGION" >/dev/null

    success "Created API Gateway REST API: $APIGATEWAY_REST_NAME ($api_id) with stage 'e2e' — intentionally non-compliant"
}

# Provision API Gateway V2 HTTP API (intentionally non-compliant: no access logging)
provision_apigateway_v2() {
    info "Provisioning API Gateway V2 HTTP API: $APIGATEWAY_V2_NAME..."

    local api_id
    api_id=$(aws apigatewayv2 get-apis \
        --query "Items[?Name=='$APIGATEWAY_V2_NAME'].ApiId | [0]" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$api_id" ] && [ "$api_id" != "None" ] && [ "$api_id" != "null" ]; then
        success "API Gateway V2 HTTP API already exists: $APIGATEWAY_V2_NAME ($api_id)"
        return
    fi

    api_id=$(aws apigatewayv2 create-api \
        --name "$APIGATEWAY_V2_NAME" \
        --protocol-type HTTP \
        --description "SigComply E2E test HTTP API" \
        --query "ApiId" --output text --region "$REGION")

    # Create a stage (no access logging — non-compliant)
    aws apigatewayv2 create-stage \
        --api-id "$api_id" \
        --stage-name "e2e" \
        --auto-deploy \
        --region "$REGION" >/dev/null

    success "Created API Gateway V2 HTTP API: $APIGATEWAY_V2_NAME ($api_id) — no access logging, intentionally non-compliant"
}

# Provision Route53 private hosted zone (intentionally non-compliant: no query logging, no DNSSEC)
provision_route53() {
    info "Provisioning Route53 private hosted zone: $ROUTE53_ZONE_NAME..."

    local zone_id
    zone_id=$(aws route53 list-hosted-zones-by-name --dns-name "$ROUTE53_ZONE_NAME" \
        --query "HostedZones[?Name=='${ROUTE53_ZONE_NAME}.'].Id | [0]" --output text 2>/dev/null) || true

    if [ -n "$zone_id" ] && [ "$zone_id" != "None" ] && [ "$zone_id" != "null" ]; then
        success "Route53 zone already exists: $ROUTE53_ZONE_NAME ($zone_id)"
        return
    fi

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    zone_id=$(aws route53 create-hosted-zone \
        --name "$ROUTE53_ZONE_NAME" \
        --caller-reference "sigcomply-e2e-$(date +%s)" \
        --vpc "VPCRegion=$REGION,VPCId=$vpc_id" \
        --hosted-zone-config "Comment=SigComply E2E test zone,PrivateZone=true" \
        --query "HostedZone.Id" --output text)
    success "Created Route53 private zone: $ROUTE53_ZONE_NAME ($zone_id) — no query logging, no DNSSEC — intentionally non-compliant"
}

# Provision CodeBuild project (intentionally non-compliant: privileged mode, no log encryption)
provision_codebuild() {
    info "Provisioning CodeBuild project: $CODEBUILD_PROJECT..."

    if aws codebuild batch-get-projects --names "$CODEBUILD_PROJECT" \
        --query "projects[0].name" --output text --region "$REGION" 2>/dev/null | grep -q "$CODEBUILD_PROJECT"; then
        success "CodeBuild project already exists: $CODEBUILD_PROJECT"
        return
    fi

    local role_arn
    role_arn=$(create_service_role "$CODEBUILD_ROLE" "codebuild.amazonaws.com")

    # CodeBuild service role needs at minimum CloudWatch Logs permissions
    aws iam put-role-policy --role-name "$CODEBUILD_ROLE" --policy-name codebuild-base \
        --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents","s3:GetObject","s3:PutObject","s3:GetBucketAcl","s3:GetBucketLocation"],"Resource":"*"}]}' 2>/dev/null || true

    # Wait for role propagation
    info "Waiting for IAM role to propagate..."
    sleep 15

    aws codebuild create-project \
        --name "$CODEBUILD_PROJECT" \
        --source '{"type":"NO_SOURCE","buildspec":"version: 0.2\nphases:\n  build:\n    commands:\n      - echo hello"}' \
        --artifacts '{"type":"NO_ARTIFACTS"}' \
        --environment "{
            \"type\": \"LINUX_CONTAINER\",
            \"image\": \"aws/codebuild/standard:5.0\",
            \"computeType\": \"BUILD_GENERAL1_SMALL\",
            \"privilegedMode\": true
        }" \
        --service-role "$role_arn" \
        --region "$REGION" >/dev/null
    success "Created CodeBuild project: $CODEBUILD_PROJECT (privileged mode — intentionally non-compliant)"
}

# Provision Kinesis stream (intentionally non-compliant: no KMS encryption)
provision_kinesis() {
    info "Provisioning Kinesis stream: $KINESIS_STREAM..."

    if aws kinesis describe-stream-summary --stream-name "$KINESIS_STREAM" \
        --region "$REGION" >/dev/null 2>&1; then
        success "Kinesis stream already exists: $KINESIS_STREAM"
        return
    fi

    aws kinesis create-stream \
        --stream-name "$KINESIS_STREAM" \
        --stream-mode-details "StreamMode=ON_DEMAND" \
        --region "$REGION"
    success "Created Kinesis stream: $KINESIS_STREAM (no KMS encryption — intentionally non-compliant)"
}

# Provision Cognito User Pool (intentionally non-compliant: MFA off, weak password)
provision_cognito() {
    info "Provisioning Cognito User Pool: $COGNITO_POOL_NAME..."

    local pool_id
    pool_id=$(aws cognito-idp list-user-pools --max-results 60 --region "$REGION" \
        --query "UserPools[?Name=='$COGNITO_POOL_NAME'].Id | [0]" --output text 2>/dev/null) || true

    if [ -n "$pool_id" ] && [ "$pool_id" != "None" ] && [ "$pool_id" != "null" ]; then
        success "Cognito User Pool already exists: $COGNITO_POOL_NAME ($pool_id)"
        return
    fi

    aws cognito-idp create-user-pool \
        --pool-name "$COGNITO_POOL_NAME" \
        --mfa-configuration OFF \
        --policies '{"PasswordPolicy":{"MinimumLength":6,"RequireUppercase":false,"RequireLowercase":false,"RequireNumbers":false,"RequireSymbols":false}}' \
        --region "$REGION" >/dev/null
    success "Created Cognito User Pool: $COGNITO_POOL_NAME (MFA off, weak password — intentionally non-compliant)"
}

# Provision ACM certificate (self-signed import — intentionally non-compliant: no CT logging)
provision_acm() {
    info "Provisioning ACM certificate (self-signed)..."

    # Check if cert with our tag already exists
    local cert_arn
    cert_arn=$(aws acm list-certificates --region "$REGION" \
        --query "CertificateSummaryList[?DomainName=='sigcomply-e2e-test.example.com'].CertificateArn | [0]" --output text 2>/dev/null) || true

    if [ -n "$cert_arn" ] && [ "$cert_arn" != "None" ] && [ "$cert_arn" != "null" ]; then
        success "ACM certificate already exists: $cert_arn"
        return
    fi

    # Generate self-signed cert
    local tmp_dir="/tmp/sigcomply-e2e-cert"
    mkdir -p "$tmp_dir"

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$tmp_dir/key.pem" \
        -out "$tmp_dir/cert.pem" \
        -subj "/CN=sigcomply-e2e-test.example.com" 2>/dev/null

    cert_arn=$(aws acm import-certificate \
        --certificate "fileb://$tmp_dir/cert.pem" \
        --private-key "fileb://$tmp_dir/key.pem" \
        --query "CertificateArn" --output text --region "$REGION")

    aws acm add-tags-to-certificate \
        --certificate-arn "$cert_arn" \
        --tags "Key=Name,Value=$ACM_CERT_NAME" \
        --region "$REGION"

    rm -rf "$tmp_dir"
    success "Imported self-signed ACM certificate: $cert_arn — intentionally non-compliant"
}

# Provision Glue job (intentionally non-compliant: no encryption, old version)
provision_glue() {
    info "Provisioning Glue job: $GLUE_JOB_NAME..."

    if aws glue get-jobs --region "$REGION" \
        --query "Jobs[?Name=='$GLUE_JOB_NAME'].Name | [0]" --output text 2>/dev/null | grep -q "$GLUE_JOB_NAME"; then
        success "Glue job already exists: $GLUE_JOB_NAME"
        return
    fi

    local role_arn
    role_arn=$(create_service_role "$GLUE_ROLE" "glue.amazonaws.com")

    aws glue create-job \
        --name "$GLUE_JOB_NAME" \
        --role "$role_arn" \
        --command '{"Name":"glueetl","ScriptLocation":"s3://sigcomply-e2e-tests/glue/script.py","PythonVersion":"3"}' \
        --glue-version "2.0" \
        --region "$REGION" >/dev/null
    success "Created Glue job: $GLUE_JOB_NAME (no encryption, version 2.0 — intentionally non-compliant)"
}

# Provision Step Functions state machine (intentionally non-compliant: no logging, no tracing)
provision_stepfunctions() {
    info "Provisioning Step Functions state machine: $SFN_STATE_MACHINE..."

    local sm_arn
    sm_arn=$(aws stepfunctions list-state-machines --region "$REGION" \
        --query "stateMachines[?name=='$SFN_STATE_MACHINE'].stateMachineArn | [0]" --output text 2>/dev/null) || true

    if [ -n "$sm_arn" ] && [ "$sm_arn" != "None" ] && [ "$sm_arn" != "null" ]; then
        success "Step Functions state machine already exists: $SFN_STATE_MACHINE ($sm_arn)"
        return
    fi

    local role_arn
    role_arn=$(create_service_role "$SFN_ROLE" "states.amazonaws.com")

    aws stepfunctions create-state-machine \
        --name "$SFN_STATE_MACHINE" \
        --definition '{"Comment":"SigComply E2E test","StartAt":"Pass","States":{"Pass":{"Type":"Pass","End":true}}}' \
        --role-arn "$role_arn" \
        --type STANDARD \
        --region "$REGION" >/dev/null
    success "Created Step Functions state machine: $SFN_STATE_MACHINE (no logging, no tracing — intentionally non-compliant)"
}

# Provision AppSync GraphQL API (intentionally non-compliant: no logging)
provision_appsync() {
    info "Provisioning AppSync API: $APPSYNC_API_NAME..."

    local api_id
    api_id=$(aws appsync list-graphql-apis --region "$REGION" \
        --query "graphqlApis[?name=='$APPSYNC_API_NAME'].apiId | [0]" --output text 2>/dev/null) || true

    if [ -n "$api_id" ] && [ "$api_id" != "None" ] && [ "$api_id" != "null" ]; then
        success "AppSync API already exists: $APPSYNC_API_NAME ($api_id)"
        return
    fi

    aws appsync create-graphql-api \
        --name "$APPSYNC_API_NAME" \
        --authentication-type API_KEY \
        --region "$REGION" >/dev/null
    success "Created AppSync API: $APPSYNC_API_NAME (no logging — intentionally non-compliant)"
}

# Provision Athena workgroup (intentionally non-compliant: no CloudWatch metrics)
provision_athena() {
    info "Provisioning Athena workgroup: $ATHENA_WORKGROUP..."

    if aws athena get-work-group --work-group "$ATHENA_WORKGROUP" \
        --region "$REGION" >/dev/null 2>&1; then
        success "Athena workgroup already exists: $ATHENA_WORKGROUP"
        return
    fi

    aws athena create-work-group \
        --name "$ATHENA_WORKGROUP" \
        --configuration '{"ResultConfiguration":{"OutputLocation":"s3://sigcomply-e2e-tests/athena-results/"},"PublishCloudWatchMetricsEnabled":false}' \
        --region "$REGION" >/dev/null
    success "Created Athena workgroup: $ATHENA_WORKGROUP (no CloudWatch metrics — intentionally non-compliant)"
}

# =============================================================================
# Expensive services (billed per-hour, spin up/down per test run)
# =============================================================================

# Helper: create a shared DB subnet group (used by Neptune, DocumentDB, DAX, Redshift, DMS)
provision_db_subnet_group() {
    info "Provisioning shared DB subnet group: $DB_SUBNET_GROUP..."

    if aws rds describe-db-subnet-groups --db-subnet-group-name "$DB_SUBNET_GROUP" \
        --region "$REGION" >/dev/null 2>&1; then
        success "DB subnet group already exists: $DB_SUBNET_GROUP"
        return
    fi

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    local subnet_ids
    subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
        --query "Subnets[?DefaultForAz==\`true\`].SubnetId" --output text --region "$REGION")

    # shellcheck disable=SC2086
    aws rds create-db-subnet-group \
        --db-subnet-group-name "$DB_SUBNET_GROUP" \
        --db-subnet-group-description "SigComply E2E test subnet group" \
        --subnet-ids $subnet_ids \
        --region "$REGION" >/dev/null
    success "Created DB subnet group: $DB_SUBNET_GROUP"
}

# Provision EKS cluster (intentionally non-compliant: no encryption, public endpoint, no logging)
provision_eks() {
    info "Provisioning EKS cluster: $EKS_CLUSTER_NAME..."

    if aws eks describe-cluster --name "$EKS_CLUSTER_NAME" --region "$REGION" >/dev/null 2>&1; then
        success "EKS cluster already exists: $EKS_CLUSTER_NAME"
        return
    fi

    # Create EKS service role
    local role_arn
    role_arn=$(aws iam get-role --role-name "$EKS_ROLE" --query "Role.Arn" --output text 2>/dev/null) || true

    if [ -z "$role_arn" ] || [ "$role_arn" = "None" ]; then
        local assume_role_policy
        assume_role_policy=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": "eks.amazonaws.com" },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
)
        role_arn=$(aws iam create-role \
            --role-name "$EKS_ROLE" \
            --assume-role-policy-document "$assume_role_policy" \
            --query "Role.Arn" --output text)
        aws iam attach-role-policy --role-name "$EKS_ROLE" \
            --policy-arn "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
        success "Created EKS role: $EKS_ROLE"
        sleep 10
    fi

    # Get subnets for EKS
    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    local subnet_ids
    subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
        --query "Subnets[?DefaultForAz==\`true\`].SubnetId | [:2]" --output json --region "$REGION")

    aws eks create-cluster \
        --name "$EKS_CLUSTER_NAME" \
        --role-arn "$role_arn" \
        --resources-vpc-config "subnetIds=$(echo "$subnet_ids" | jq -r 'join(",")'),endpointPublicAccess=true,endpointPrivateAccess=false" \
        --region "$REGION" >/dev/null
    success "Created EKS cluster: $EKS_CLUSTER_NAME (no encryption, public endpoint, no logging — intentionally non-compliant)"
    info "EKS cluster creation takes ~15 minutes. Continuing with other resources..."
}

# Provision MSK Serverless cluster (intentionally non-compliant: minimal config)
provision_msk() {
    info "Provisioning MSK Serverless cluster: $MSK_CLUSTER_NAME..."

    local cluster_arn
    cluster_arn=$(aws kafka list-clusters-v2 --region "$REGION" \
        --query "ClusterInfoList[?ClusterName=='$MSK_CLUSTER_NAME'].ClusterArn | [0]" --output text 2>/dev/null) || true

    if [ -n "$cluster_arn" ] && [ "$cluster_arn" != "None" ] && [ "$cluster_arn" != "null" ]; then
        success "MSK cluster already exists: $MSK_CLUSTER_NAME"
        return
    fi

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    local subnet_ids
    subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
        --query "Subnets[?DefaultForAz==\`true\`].SubnetId | [:2]" --output json --region "$REGION")

    local sg_id
    sg_id=$(aws ec2 describe-security-groups \
        --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=default" \
        --query "SecurityGroups[0].GroupId" --output text --region "$REGION")

    local serverless_config
    serverless_config=$(cat <<MSKCONFIG
{
    "ClusterName": "${MSK_CLUSTER_NAME}",
    "Serverless": {
        "VpcConfigs": [
            {
                "SubnetIds": $(echo "$subnet_ids" | jq -c '.'),
                "SecurityGroupIds": ["${sg_id}"]
            }
        ],
        "ClientAuthentication": {
            "Sasl": {
                "Iam": { "Enabled": true }
            }
        }
    }
}
MSKCONFIG
)

    aws kafka create-cluster-v2 \
        --cli-input-json "$serverless_config" \
        --region "$REGION" >/dev/null
    success "Created MSK Serverless cluster: $MSK_CLUSTER_NAME — intentionally non-compliant"
}

# Provision Neptune cluster (intentionally non-compliant: no encryption, no audit logging)
provision_neptune() {
    info "Provisioning Neptune cluster: $NEPTUNE_CLUSTER..."

    if aws neptune describe-db-clusters --db-cluster-identifier "$NEPTUNE_CLUSTER" \
        --region "$REGION" >/dev/null 2>&1; then
        success "Neptune cluster already exists: $NEPTUNE_CLUSTER"
        return
    fi

    # Create Neptune subnet group
    if ! aws neptune describe-db-subnet-groups --db-subnet-group-name "$NEPTUNE_SUBNET_GROUP" \
        --region "$REGION" >/dev/null 2>&1; then
        local vpc_id
        vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
            --query "Vpcs[0].VpcId" --output text --region "$REGION")
        local subnet_ids
        subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
            --query "Subnets[?DefaultForAz==\`true\`].SubnetId" --output text --region "$REGION")
        # shellcheck disable=SC2086
        aws neptune create-db-subnet-group \
            --db-subnet-group-name "$NEPTUNE_SUBNET_GROUP" \
            --db-subnet-group-description "SigComply E2E Neptune subnet group" \
            --subnet-ids $subnet_ids \
            --region "$REGION" >/dev/null
        success "Created Neptune subnet group: $NEPTUNE_SUBNET_GROUP"
    fi

    aws neptune create-db-cluster \
        --db-cluster-identifier "$NEPTUNE_CLUSTER" \
        --engine neptune \
        --no-storage-encrypted \
        --db-subnet-group-name "$NEPTUNE_SUBNET_GROUP" \
        --region "$REGION" >/dev/null

    aws neptune create-db-instance \
        --db-instance-identifier "$NEPTUNE_INSTANCE" \
        --db-cluster-identifier "$NEPTUNE_CLUSTER" \
        --db-instance-class db.t3.medium \
        --engine neptune \
        --region "$REGION" >/dev/null
    success "Created Neptune cluster: $NEPTUNE_CLUSTER (no encryption, no audit logging — intentionally non-compliant)"
    info "Neptune cluster creation takes ~10-15 minutes. Continuing..."
}

# Provision OpenSearch domain (intentionally non-compliant: no encryption, no fine-grained access)
provision_opensearch() {
    info "Provisioning OpenSearch domain: $OPENSEARCH_DOMAIN..."

    if aws opensearch describe-domain --domain-name "$OPENSEARCH_DOMAIN" \
        --region "$REGION" >/dev/null 2>&1; then
        success "OpenSearch domain already exists: $OPENSEARCH_DOMAIN"
        return
    fi

    aws opensearch create-domain \
        --domain-name "$OPENSEARCH_DOMAIN" \
        --engine-version "OpenSearch_2.11" \
        --cluster-config "InstanceType=t3.small.search,InstanceCount=1" \
        --ebs-options "EBSEnabled=true,VolumeType=gp3,VolumeSize=10" \
        --no-node-to-node-encryption-options \
        --no-encrypt-at-rest-options \
        --domain-endpoint-options "EnforceHTTPS=false" \
        --access-policies "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"es:*\",\"Resource\":\"arn:aws:es:${REGION}:${EXPECTED_ACCOUNT_ID}:domain/${OPENSEARCH_DOMAIN}/*\"}]}" \
        --region "$REGION" >/dev/null
    success "Created OpenSearch domain: $OPENSEARCH_DOMAIN (no encryption, open access — intentionally non-compliant)"
    info "OpenSearch domain creation takes ~10-15 minutes. Continuing..."
}

# Provision Redshift cluster (intentionally non-compliant: no encryption, no audit logging, public)
provision_redshift() {
    info "Provisioning Redshift cluster: $REDSHIFT_CLUSTER..."

    if aws redshift describe-clusters --cluster-identifier "$REDSHIFT_CLUSTER" \
        --region "$REGION" >/dev/null 2>&1; then
        success "Redshift cluster already exists: $REDSHIFT_CLUSTER"
        return
    fi

    # Create Redshift subnet group
    if ! aws redshift describe-cluster-subnet-groups --cluster-subnet-group-name "$REDSHIFT_SUBNET_GROUP" \
        --region "$REGION" >/dev/null 2>&1; then
        local vpc_id
        vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
            --query "Vpcs[0].VpcId" --output text --region "$REGION")
        local subnet_ids
        subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
            --query "Subnets[?DefaultForAz==\`true\`].SubnetId" --output text --region "$REGION")
        # shellcheck disable=SC2086
        aws redshift create-cluster-subnet-group \
            --cluster-subnet-group-name "$REDSHIFT_SUBNET_GROUP" \
            --description "SigComply E2E Redshift subnet group" \
            --subnet-ids $subnet_ids \
            --region "$REGION" >/dev/null
        success "Created Redshift subnet group: $REDSHIFT_SUBNET_GROUP"
    fi

    aws redshift create-cluster \
        --cluster-identifier "$REDSHIFT_CLUSTER" \
        --node-type dc2.large \
        --number-of-nodes 1 \
        --master-username admin \
        --master-user-password "E2eTestPass123!" \
        --cluster-subnet-group-name "$REDSHIFT_SUBNET_GROUP" \
        --no-encrypted \
        --publicly-accessible \
        --region "$REGION" >/dev/null
    success "Created Redshift cluster: $REDSHIFT_CLUSTER (no encryption, public — intentionally non-compliant)"
    info "Redshift cluster creation takes ~10 minutes. Continuing..."
}

# Provision Redshift Serverless (intentionally non-compliant: no encryption)
provision_redshift_serverless() {
    info "Provisioning Redshift Serverless: $REDSHIFT_SL_NAMESPACE..."

    local ns_status
    ns_status=$(aws redshift-serverless get-namespace --namespace-name "$REDSHIFT_SL_NAMESPACE" \
        --query "namespace.status" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$ns_status" ] && [ "$ns_status" != "None" ]; then
        success "Redshift Serverless namespace already exists: $REDSHIFT_SL_NAMESPACE"
        return
    fi

    aws redshift-serverless create-namespace \
        --namespace-name "$REDSHIFT_SL_NAMESPACE" \
        --admin-username admin \
        --admin-user-password "E2eTestPass123!" \
        --region "$REGION" >/dev/null
    success "Created Redshift Serverless namespace: $REDSHIFT_SL_NAMESPACE"

    # Create workgroup
    local wg_status
    wg_status=$(aws redshift-serverless get-workgroup --workgroup-name "$REDSHIFT_SL_WORKGROUP" \
        --query "workgroup.status" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$wg_status" ] && [ "$wg_status" != "None" ]; then
        success "Redshift Serverless workgroup already exists: $REDSHIFT_SL_WORKGROUP"
        return
    fi

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")
    local subnet_ids
    subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
        --query "Subnets[?DefaultForAz==\`true\`].SubnetId" --output json --region "$REGION")
    local sg_id
    sg_id=$(aws ec2 describe-security-groups \
        --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=default" \
        --query "SecurityGroups[0].GroupId" --output text --region "$REGION")

    aws redshift-serverless create-workgroup \
        --workgroup-name "$REDSHIFT_SL_WORKGROUP" \
        --namespace-name "$REDSHIFT_SL_NAMESPACE" \
        --base-capacity 8 \
        --subnet-ids $(echo "$subnet_ids" | jq -r '.[]') \
        --security-group-ids "$sg_id" \
        --publicly-accessible \
        --region "$REGION" >/dev/null
    success "Created Redshift Serverless workgroup: $REDSHIFT_SL_WORKGROUP (publicly accessible — intentionally non-compliant)"
}

# Provision EMR cluster (intentionally non-compliant: no encryption, no logging)
provision_emr() {
    info "Provisioning EMR cluster: $EMR_CLUSTER_NAME..."

    # Check if cluster already exists (running/waiting state)
    local cluster_id
    cluster_id=$(aws emr list-clusters --active --region "$REGION" \
        --query "Clusters[?Name=='$EMR_CLUSTER_NAME'].Id | [0]" --output text 2>/dev/null) || true

    if [ -n "$cluster_id" ] && [ "$cluster_id" != "None" ] && [ "$cluster_id" != "null" ]; then
        success "EMR cluster already exists: $EMR_CLUSTER_NAME ($cluster_id)"
        return
    fi

    # Create EMR service role
    local emr_role_arn
    emr_role_arn=$(aws iam get-role --role-name "$EMR_ROLE" --query "Role.Arn" --output text 2>/dev/null) || true

    if [ -z "$emr_role_arn" ] || [ "$emr_role_arn" = "None" ]; then
        local assume_role_policy
        assume_role_policy=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": "elasticmapreduce.amazonaws.com" },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
)
        emr_role_arn=$(aws iam create-role \
            --role-name "$EMR_ROLE" \
            --assume-role-policy-document "$assume_role_policy" \
            --query "Role.Arn" --output text)
        aws iam attach-role-policy --role-name "$EMR_ROLE" \
            --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
        success "Created EMR role: $EMR_ROLE"
    fi

    # Create EMR EC2 role + instance profile
    local ec2_role_arn
    ec2_role_arn=$(aws iam get-role --role-name "$EMR_EC2_ROLE" --query "Role.Arn" --output text 2>/dev/null) || true

    if [ -z "$ec2_role_arn" ] || [ "$ec2_role_arn" = "None" ]; then
        local ec2_assume_policy
        ec2_assume_policy=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": "ec2.amazonaws.com" },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
)
        aws iam create-role \
            --role-name "$EMR_EC2_ROLE" \
            --assume-role-policy-document "$ec2_assume_policy" >/dev/null
        aws iam attach-role-policy --role-name "$EMR_EC2_ROLE" \
            --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
        success "Created EMR EC2 role: $EMR_EC2_ROLE"
    fi

    # Create instance profile if not exists
    if ! aws iam get-instance-profile --instance-profile-name "$EMR_INSTANCE_PROFILE" >/dev/null 2>&1; then
        aws iam create-instance-profile --instance-profile-name "$EMR_INSTANCE_PROFILE" >/dev/null
        aws iam add-role-to-instance-profile \
            --instance-profile-name "$EMR_INSTANCE_PROFILE" \
            --role-name "$EMR_EC2_ROLE"
        success "Created EMR instance profile: $EMR_INSTANCE_PROFILE"
        sleep 10
    fi

    aws emr create-cluster \
        --name "$EMR_CLUSTER_NAME" \
        --release-label emr-6.15.0 \
        --applications Name=Spark \
        --instance-groups '[{"InstanceGroupType":"MASTER","InstanceCount":1,"InstanceType":"m5.xlarge"}]' \
        --service-role "$EMR_ROLE" \
        --ec2-attributes "InstanceProfile=$EMR_INSTANCE_PROFILE" \
        --auto-terminate \
        --step-concurrency-level 1 \
        --region "$REGION" >/dev/null
    success "Created EMR cluster: $EMR_CLUSTER_NAME (no encryption, no logging — intentionally non-compliant)"
}

# Provision DocumentDB cluster (intentionally non-compliant: no encryption, no audit logging)
provision_docdb() {
    info "Provisioning DocumentDB cluster: $DOCDB_CLUSTER..."

    if aws docdb describe-db-clusters --db-cluster-identifier "$DOCDB_CLUSTER" \
        --region "$REGION" >/dev/null 2>&1; then
        success "DocumentDB cluster already exists: $DOCDB_CLUSTER"
        return
    fi

    # Create DocumentDB subnet group
    if ! aws docdb describe-db-subnet-groups --db-subnet-group-name "$DOCDB_SUBNET_GROUP" \
        --region "$REGION" >/dev/null 2>&1; then
        local vpc_id
        vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
            --query "Vpcs[0].VpcId" --output text --region "$REGION")
        local subnet_ids
        subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
            --query "Subnets[?DefaultForAz==\`true\`].SubnetId" --output text --region "$REGION")
        # shellcheck disable=SC2086
        aws docdb create-db-subnet-group \
            --db-subnet-group-name "$DOCDB_SUBNET_GROUP" \
            --db-subnet-group-description "SigComply E2E DocumentDB subnet group" \
            --subnet-ids $subnet_ids \
            --region "$REGION" >/dev/null
        success "Created DocumentDB subnet group: $DOCDB_SUBNET_GROUP"
    fi

    aws docdb create-db-cluster \
        --db-cluster-identifier "$DOCDB_CLUSTER" \
        --engine docdb \
        --master-username admin \
        --master-user-password "E2eTestPass123!" \
        --no-storage-encrypted \
        --db-subnet-group-name "$DOCDB_SUBNET_GROUP" \
        --region "$REGION" >/dev/null

    aws docdb create-db-instance \
        --db-instance-identifier "$DOCDB_INSTANCE" \
        --db-cluster-identifier "$DOCDB_CLUSTER" \
        --db-instance-class db.t3.medium \
        --engine docdb \
        --region "$REGION" >/dev/null
    success "Created DocumentDB cluster: $DOCDB_CLUSTER (no encryption, no audit logging — intentionally non-compliant)"
    info "DocumentDB cluster creation takes ~10-15 minutes. Continuing..."
}

# Provision Amazon MQ broker (intentionally non-compliant: no encryption, no audit logging)
provision_mq() {
    info "Provisioning Amazon MQ broker: $MQ_BROKER_NAME..."

    local broker_id
    broker_id=$(aws mq list-brokers --region "$REGION" \
        --query "BrokerSummaries[?BrokerName=='$MQ_BROKER_NAME'].BrokerId | [0]" --output text 2>/dev/null) || true

    if [ -n "$broker_id" ] && [ "$broker_id" != "None" ] && [ "$broker_id" != "null" ]; then
        success "MQ broker already exists: $MQ_BROKER_NAME ($broker_id)"
        return
    fi

    aws mq create-broker \
        --broker-name "$MQ_BROKER_NAME" \
        --engine-type ACTIVEMQ \
        --engine-version "5.18" \
        --host-instance-type "mq.t3.micro" \
        --deployment-mode SINGLE_INSTANCE \
        --publicly-accessible \
        --no-auto-minor-version-upgrade \
        --users '[{"ConsoleAccess":true,"Username":"admin","Password":"E2eTestPass123!"}]' \
        --region "$REGION" >/dev/null
    success "Created MQ broker: $MQ_BROKER_NAME (public, no encryption — intentionally non-compliant)"
}

# Provision DMS replication instance (intentionally non-compliant: public, no encryption)
provision_dms() {
    info "Provisioning DMS replication instance: $DMS_INSTANCE..."

    if aws dms describe-replication-instances --region "$REGION" \
        --filters "Name=replication-instance-id,Values=$DMS_INSTANCE" \
        --query "ReplicationInstances[0].ReplicationInstanceIdentifier" --output text 2>/dev/null | grep -q "$DMS_INSTANCE"; then
        success "DMS replication instance already exists: $DMS_INSTANCE"
        return
    fi

    # Create DMS subnet group
    if ! aws dms describe-replication-subnet-groups --region "$REGION" \
        --filters "Name=replication-subnet-group-id,Values=$DMS_SUBNET_GROUP" \
        --query "ReplicationSubnetGroups[0]" --output text 2>/dev/null | grep -q "$DMS_SUBNET_GROUP"; then
        local vpc_id
        vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
            --query "Vpcs[0].VpcId" --output text --region "$REGION")
        local subnet_ids
        subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
            --query "Subnets[?DefaultForAz==\`true\`].SubnetId" --output text --region "$REGION")
        # shellcheck disable=SC2086
        aws dms create-replication-subnet-group \
            --replication-subnet-group-identifier "$DMS_SUBNET_GROUP" \
            --replication-subnet-group-description "SigComply E2E DMS subnet group" \
            --subnet-ids $subnet_ids \
            --region "$REGION" >/dev/null
        success "Created DMS subnet group: $DMS_SUBNET_GROUP"
    fi

    aws dms create-replication-instance \
        --replication-instance-identifier "$DMS_INSTANCE" \
        --replication-instance-class dms.t3.micro \
        --no-multi-az \
        --publicly-accessible \
        --replication-subnet-group-identifier "$DMS_SUBNET_GROUP" \
        --region "$REGION" >/dev/null
    success "Created DMS replication instance: $DMS_INSTANCE (public, no encryption — intentionally non-compliant)"
}

# Provision Network Firewall (intentionally non-compliant: no logging)
provision_network_firewall() {
    info "Provisioning Network Firewall: $NFW_FIREWALL..."

    if aws network-firewall describe-firewall --firewall-name "$NFW_FIREWALL" \
        --region "$REGION" >/dev/null 2>&1; then
        success "Network Firewall already exists: $NFW_FIREWALL"
        return
    fi

    # Create firewall policy first
    local policy_arn
    policy_arn=$(aws network-firewall describe-firewall-policy \
        --firewall-policy-name "$NFW_POLICY" \
        --query "FirewallPolicyResponse.FirewallPolicyArn" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$policy_arn" ] || [ "$policy_arn" = "None" ]; then
        policy_arn=$(aws network-firewall create-firewall-policy \
            --firewall-policy-name "$NFW_POLICY" \
            --firewall-policy '{"StatelessDefaultActions":["aws:pass"],"StatelessFragmentDefaultActions":["aws:pass"]}' \
            --query "FirewallPolicyResponse.FirewallPolicyArn" --output text --region "$REGION")
        success "Created Network Firewall policy: $NFW_POLICY"
    fi

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    local subnet_id
    subnet_id=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
        --query "Subnets[?DefaultForAz==\`true\`].SubnetId | [0]" --output text --region "$REGION")

    aws network-firewall create-firewall \
        --firewall-name "$NFW_FIREWALL" \
        --firewall-policy-arn "$policy_arn" \
        --vpc-id "$vpc_id" \
        --subnet-mappings "SubnetId=$subnet_id" \
        --region "$REGION" >/dev/null
    success "Created Network Firewall: $NFW_FIREWALL (no logging — intentionally non-compliant)"
}

# Provision FSx for Lustre (intentionally non-compliant: no encryption)
provision_fsx() {
    info "Provisioning FSx filesystem: $FSX_NAME..."

    local fs_id
    fs_id=$(aws fsx describe-file-systems --region "$REGION" \
        --query "FileSystems[?tags[?Key=='Name' && Value=='$FSX_NAME']].FileSystemId | [0]" --output text 2>/dev/null) || true

    if [ -n "$fs_id" ] && [ "$fs_id" != "None" ] && [ "$fs_id" != "null" ]; then
        success "FSx filesystem already exists: $FSX_NAME ($fs_id)"
        return
    fi

    local vpc_id
    vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
        --query "Vpcs[0].VpcId" --output text --region "$REGION")

    local subnet_id
    subnet_id=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
        --query "Subnets[?DefaultForAz==\`true\`].SubnetId | [0]" --output text --region "$REGION")

    aws fsx create-file-system \
        --file-system-type LUSTRE \
        --storage-capacity 1200 \
        --storage-type SSD \
        --lustre-configuration "DeploymentType=SCRATCH_1" \
        --subnet-ids "$subnet_id" \
        --tags "Key=Name,Value=$FSX_NAME" \
        --region "$REGION" >/dev/null
    success "Created FSx Lustre filesystem: $FSX_NAME (SCRATCH_1, no encryption — intentionally non-compliant)"
}

# Provision Transfer Family server (intentionally non-compliant: FTP, no logging)
provision_transfer() {
    info "Provisioning Transfer Family server: $TRANSFER_SERVER..."

    local server_id
    server_id=$(aws transfer list-servers --region "$REGION" \
        --query "Servers[?Tags[?Key=='Name' && Value=='$TRANSFER_SERVER']].ServerId | [0]" --output text 2>/dev/null) || true

    if [ -n "$server_id" ] && [ "$server_id" != "None" ] && [ "$server_id" != "null" ]; then
        success "Transfer server already exists: $TRANSFER_SERVER ($server_id)"
        return
    fi

    server_id=$(aws transfer create-server \
        --protocols SFTP \
        --endpoint-type PUBLIC \
        --tags "Key=Name,Value=$TRANSFER_SERVER" \
        --query "ServerId" --output text --region "$REGION")
    success "Created Transfer server: $TRANSFER_SERVER ($server_id) (public, no logging — intentionally non-compliant)"
}

# Provision SageMaker notebook instance (intentionally non-compliant: no encryption, root access, direct internet)
provision_sagemaker() {
    info "Provisioning SageMaker notebook: $SAGEMAKER_NOTEBOOK..."

    local status
    status=$(aws sagemaker describe-notebook-instance --notebook-instance-name "$SAGEMAKER_NOTEBOOK" \
        --query "NotebookInstanceStatus" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$status" ] && [ "$status" != "None" ]; then
        success "SageMaker notebook already exists: $SAGEMAKER_NOTEBOOK (status: $status)"
        return
    fi

    local role_arn
    role_arn=$(create_service_role "$SAGEMAKER_ROLE" "sagemaker.amazonaws.com")

    aws sagemaker create-notebook-instance \
        --notebook-instance-name "$SAGEMAKER_NOTEBOOK" \
        --instance-type ml.t3.medium \
        --role-arn "$role_arn" \
        --direct-internet-access Enabled \
        --root-access Enabled \
        --region "$REGION" >/dev/null
    success "Created SageMaker notebook: $SAGEMAKER_NOTEBOOK (root access, direct internet — intentionally non-compliant)"
}

# Provision DAX cluster (intentionally non-compliant: no encryption)
provision_dax() {
    info "Provisioning DAX cluster: $DAX_CLUSTER..."

    if aws dax describe-clusters --cluster-names "$DAX_CLUSTER" \
        --region "$REGION" >/dev/null 2>&1; then
        success "DAX cluster already exists: $DAX_CLUSTER"
        return
    fi

    # Create DAX subnet group
    if ! aws dax describe-subnet-groups --subnet-group-names "$DAX_SUBNET_GROUP" \
        --region "$REGION" >/dev/null 2>&1; then
        local vpc_id
        vpc_id=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" \
            --query "Vpcs[0].VpcId" --output text --region "$REGION")
        local subnet_ids
        subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
            --query "Subnets[?DefaultForAz==\`true\`].SubnetId" --output text --region "$REGION")
        # shellcheck disable=SC2086
        aws dax create-subnet-group \
            --subnet-group-name "$DAX_SUBNET_GROUP" \
            --description "SigComply E2E DAX subnet group" \
            --subnet-ids $subnet_ids \
            --region "$REGION" >/dev/null
        success "Created DAX subnet group: $DAX_SUBNET_GROUP"
    fi

    # Create DAX role
    local role_arn
    role_arn=$(aws iam get-role --role-name "$DAX_ROLE" --query "Role.Arn" --output text 2>/dev/null) || true

    if [ -z "$role_arn" ] || [ "$role_arn" = "None" ]; then
        local assume_role_policy
        assume_role_policy=$(cat <<'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": "dax.amazonaws.com" },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
)
        role_arn=$(aws iam create-role \
            --role-name "$DAX_ROLE" \
            --assume-role-policy-document "$assume_role_policy" \
            --query "Role.Arn" --output text)
        aws iam attach-role-policy --role-name "$DAX_ROLE" \
            --policy-arn "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
        success "Created DAX role: $DAX_ROLE"
        sleep 10
    fi

    aws dax create-cluster \
        --cluster-name "$DAX_CLUSTER" \
        --node-type dax.t3.small \
        --replication-factor 1 \
        --iam-role-arn "$role_arn" \
        --subnet-group "$DAX_SUBNET_GROUP" \
        --region "$REGION" >/dev/null
    success "Created DAX cluster: $DAX_CLUSTER (no encryption — intentionally non-compliant)"
}

# Provision Elastic Beanstalk (intentionally non-compliant: no HTTPS, basic health)
provision_elasticbeanstalk() {
    info "Provisioning Elastic Beanstalk: $EB_APP_NAME..."

    # Create application
    if aws elasticbeanstalk describe-applications --application-names "$EB_APP_NAME" \
        --query "Applications[0].ApplicationName" --output text --region "$REGION" 2>/dev/null | grep -q "$EB_APP_NAME"; then
        success "Elastic Beanstalk app already exists: $EB_APP_NAME"
    else
        aws elasticbeanstalk create-application \
            --application-name "$EB_APP_NAME" \
            --description "SigComply E2E test application" \
            --region "$REGION" >/dev/null
        success "Created Elastic Beanstalk app: $EB_APP_NAME"
    fi

    # Check if environment exists
    local env_status
    env_status=$(aws elasticbeanstalk describe-environments \
        --application-name "$EB_APP_NAME" \
        --environment-names "$EB_ENV_NAME" \
        --query "Environments[?Status!='Terminated'].Status | [0]" --output text --region "$REGION" 2>/dev/null) || true

    if [ -n "$env_status" ] && [ "$env_status" != "None" ] && [ "$env_status" != "null" ]; then
        success "Elastic Beanstalk environment already exists: $EB_ENV_NAME (status: $env_status)"
        return
    fi

    # Get latest Docker solution stack
    local solution_stack
    solution_stack=$(aws elasticbeanstalk list-available-solution-stacks \
        --query "SolutionStacks[?contains(@, 'Docker') && contains(@, 'Amazon Linux 2023')] | [0]" \
        --output text --region "$REGION")

    aws elasticbeanstalk create-environment \
        --application-name "$EB_APP_NAME" \
        --environment-name "$EB_ENV_NAME" \
        --solution-stack-name "$solution_stack" \
        --option-settings \
            "Namespace=aws:autoscaling:launchconfiguration,OptionName=InstanceType,Value=t3.micro" \
            "Namespace=aws:elasticbeanstalk:environment,OptionName=EnvironmentType,Value=SingleInstance" \
            "Namespace=aws:elasticbeanstalk:healthreporting:system,OptionName=SystemType,Value=basic" \
        --region "$REGION" >/dev/null
    success "Created Elastic Beanstalk environment: $EB_ENV_NAME (basic health, no HTTPS — intentionally non-compliant)"
}

# Provision DataSync task (intentionally non-compliant: no encryption)
provision_datasync() {
    info "Provisioning DataSync task: $DATASYNC_TASK_NAME..."

    local task_arn
    task_arn=$(aws datasync list-tasks --region "$REGION" \
        --query "Tasks[?Tags[?Key=='Name' && Value=='$DATASYNC_TASK_NAME']].TaskArn | [0]" --output text 2>/dev/null) || true

    if [ -n "$task_arn" ] && [ "$task_arn" != "None" ] && [ "$task_arn" != "null" ]; then
        success "DataSync task already exists: $DATASYNC_TASK_NAME"
        return
    fi

    # Create source S3 location
    local src_arn
    src_arn=$(aws datasync create-location-s3 \
        --s3-bucket-arn "arn:aws:s3:::$S3_BUCKET" \
        --s3-config "BucketAccessRoleArn=$(aws iam get-role --role-name "$LAMBDA_ROLE" --query "Role.Arn" --output text 2>/dev/null)" \
        --subdirectory "/datasync-src" \
        --tags "Key=Name,Value=${DATASYNC_TASK_NAME}-src" \
        --query "LocationArn" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$src_arn" ] || [ "$src_arn" = "None" ]; then
        warn "Failed to create DataSync source location. Skipping DataSync."
        return
    fi

    # Create destination S3 location
    local dst_arn
    dst_arn=$(aws datasync create-location-s3 \
        --s3-bucket-arn "arn:aws:s3:::$S3_BUCKET" \
        --s3-config "BucketAccessRoleArn=$(aws iam get-role --role-name "$LAMBDA_ROLE" --query "Role.Arn" --output text 2>/dev/null)" \
        --subdirectory "/datasync-dst" \
        --tags "Key=Name,Value=${DATASYNC_TASK_NAME}-dst" \
        --query "LocationArn" --output text --region "$REGION" 2>/dev/null) || true

    if [ -z "$dst_arn" ] || [ "$dst_arn" = "None" ]; then
        warn "Failed to create DataSync destination location. Skipping DataSync."
        return
    fi

    aws datasync create-task \
        --source-location-arn "$src_arn" \
        --destination-location-arn "$dst_arn" \
        --name "$DATASYNC_TASK_NAME" \
        --tags "Key=Name,Value=$DATASYNC_TASK_NAME" \
        --region "$REGION" >/dev/null
    success "Created DataSync task: $DATASYNC_TASK_NAME — intentionally non-compliant"
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
    echo "    - IAM policies: ${POSITIVE_POLICY_NAMES[*]}, $NEGATIVE_POLICY_NAME"
    echo "    - S3 bucket: $S3_BUCKET"
    echo "    - CloudTrail: $CLOUDTRAIL_NAME (bucket: $CLOUDTRAIL_BUCKET)"
    echo "    - CloudWatch log group: $LOG_GROUP_NAME"
    echo "    - KMS key: $KMS_ALIAS"
    echo "    - ECR repo: $ECR_REPO"
    echo "    - RDS instance: $RDS_INSTANCE"
    echo "    - DynamoDB table: $DYNAMODB_TABLE"
    echo "    - Lambda function: $LAMBDA_FUNCTION (role: $LAMBDA_ROLE)"
    echo "    - Secrets Manager secret: $SECRET_NAME"
    echo "    - ALB: $ALB_NAME (HTTP-only — intentionally non-compliant)"
    echo "    - SNS topic: $SNS_TOPIC_NAME (no KMS — intentionally non-compliant)"
    echo "    - SQS queue: $SQS_QUEUE_NAME (no encryption, no DLQ — intentionally non-compliant)"
    echo "    - EFS filesystem: $EFS_NAME (no backup — intentionally non-compliant)"
    echo "    - Backup vault: $BACKUP_VAULT_NAME (no vault lock — intentionally non-compliant)"
    echo "    - VPC flow logs: enabled on default VPC"
    echo "    - Launch Template: $LAUNCH_TEMPLATE_NAME (IMDSv1 — intentionally non-compliant)"
    echo "    - EC2 Instance: $EC2_INSTANCE_NAME (public IP, no monitoring — intentionally non-compliant)"
    echo "    - EBS Volume: $EBS_VOLUME_NAME (unencrypted — intentionally non-compliant)"
    echo "    - EBS Snapshot: from $EBS_VOLUME_NAME (unencrypted — intentionally non-compliant)"
    echo "    - VPC Endpoint: S3 gateway endpoint"
    echo "    - ECS Cluster: $ECS_CLUSTER_NAME (no insights — intentionally non-compliant)"
    echo "    - ECS Task Def: $ECS_TASK_FAMILY (privileged, root — intentionally non-compliant)"
    echo "    - CloudFront: distribution (allow-all, no WAF — intentionally non-compliant)"
    echo "    - API Gateway REST: $APIGATEWAY_REST_NAME (no auth — intentionally non-compliant)"
    echo "    - API Gateway V2: $APIGATEWAY_V2_NAME (no logging — intentionally non-compliant)"
    echo "    - Route53: $ROUTE53_ZONE_NAME (no query logging — intentionally non-compliant)"
    echo "    - CodeBuild: $CODEBUILD_PROJECT (privileged — intentionally non-compliant)"
    echo "    - Kinesis: $KINESIS_STREAM (no encryption — intentionally non-compliant)"
    echo "    - Cognito: $COGNITO_POOL_NAME (MFA off — intentionally non-compliant)"
    echo "    - ACM: self-signed cert (intentionally non-compliant)"
    echo "    - Glue: $GLUE_JOB_NAME (no encryption, v2.0 — intentionally non-compliant)"
    echo "    - Step Functions: $SFN_STATE_MACHINE (no logging — intentionally non-compliant)"
    echo "    - AppSync: $APPSYNC_API_NAME (no logging — intentionally non-compliant)"
    echo "    - Athena: $ATHENA_WORKGROUP (no metrics — intentionally non-compliant)"
    echo "    - ASG: $ASG_NAME (desired=0, EC2 health — intentionally non-compliant)"
    echo ""
    echo "  Expensive resources (billed per-hour):"
    echo "    - EKS: $EKS_CLUSTER_NAME (no encryption, public — intentionally non-compliant)"
    echo "    - MSK Serverless: $MSK_CLUSTER_NAME"
    echo "    - Neptune: $NEPTUNE_CLUSTER (no encryption — intentionally non-compliant)"
    echo "    - OpenSearch: $OPENSEARCH_DOMAIN (no encryption — intentionally non-compliant)"
    echo "    - Redshift: $REDSHIFT_CLUSTER (no encryption, public — intentionally non-compliant)"
    echo "    - Redshift Serverless: $REDSHIFT_SL_NAMESPACE"
    echo "    - EMR: $EMR_CLUSTER_NAME (no encryption — intentionally non-compliant)"
    echo "    - DocumentDB: $DOCDB_CLUSTER (no encryption — intentionally non-compliant)"
    echo "    - Amazon MQ: $MQ_BROKER_NAME (public — intentionally non-compliant)"
    echo "    - DMS: $DMS_INSTANCE (public — intentionally non-compliant)"
    echo "    - Network Firewall: $NFW_FIREWALL (no logging — intentionally non-compliant)"
    echo "    - FSx Lustre: $FSX_NAME (SCRATCH_1 — intentionally non-compliant)"
    echo "    - Transfer Family: $TRANSFER_SERVER (FTP only — intentionally non-compliant)"
    echo "    - SageMaker: $SAGEMAKER_NOTEBOOK (root access — intentionally non-compliant)"
    echo "    - DAX: $DAX_CLUSTER (no encryption — intentionally non-compliant)"
    echo "    - Elastic Beanstalk: $EB_APP_NAME/$EB_ENV_NAME (basic health — intentionally non-compliant)"
    echo "    - DataSync: $DATASYNC_TASK_NAME"
    echo ""
    warn "Remember to run teardown-aws.sh after testing to stop per-hour billing!"
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
    provision_elbv2
    provision_sns
    provision_sqs
    provision_efs
    provision_backup_vault
    provision_vpc_flow_logs

    # New resources — each wrapped with || warn so one failure doesn't abort the rest
    provision_launch_template || warn "Launch template provisioning failed, continuing..."
    provision_ec2_instance || warn "EC2 instance provisioning failed, continuing..."
    provision_ebs_volume || warn "EBS volume provisioning failed, continuing..."
    provision_ebs_snapshot || warn "EBS snapshot provisioning failed, continuing..."
    provision_vpc_endpoint || warn "VPC endpoint provisioning failed, continuing..."
    provision_ecs || warn "ECS provisioning failed, continuing..."
    provision_cloudfront || warn "CloudFront provisioning failed, continuing..."
    provision_apigateway_rest || warn "API Gateway REST provisioning failed, continuing..."
    provision_apigateway_v2 || warn "API Gateway V2 provisioning failed, continuing..."
    provision_route53 || warn "Route53 provisioning failed, continuing..."
    provision_codebuild || warn "CodeBuild provisioning failed, continuing..."
    provision_kinesis || warn "Kinesis provisioning failed, continuing..."
    provision_cognito || warn "Cognito provisioning failed, continuing..."
    provision_acm || warn "ACM provisioning failed, continuing..."
    provision_glue || warn "Glue provisioning failed, continuing..."
    provision_stepfunctions || warn "Step Functions provisioning failed, continuing..."
    provision_appsync || warn "AppSync provisioning failed, continuing..."
    provision_athena || warn "Athena provisioning failed, continuing..."
    provision_asg || warn "ASG provisioning failed, continuing..."

    # Expensive services (billed per-hour — spin up/down per test run)
    provision_db_subnet_group || warn "DB subnet group provisioning failed, continuing..."
    provision_eks || warn "EKS provisioning failed, continuing..."
    provision_msk || warn "MSK provisioning failed, continuing..."
    provision_neptune || warn "Neptune provisioning failed, continuing..."
    provision_opensearch || warn "OpenSearch provisioning failed, continuing..."
    provision_redshift || warn "Redshift provisioning failed, continuing..."
    provision_redshift_serverless || warn "Redshift Serverless provisioning failed, continuing..."
    provision_emr || warn "EMR provisioning failed, continuing..."
    provision_docdb || warn "DocumentDB provisioning failed, continuing..."
    provision_mq || warn "MQ provisioning failed, continuing..."
    provision_dms || warn "DMS provisioning failed, continuing..."
    provision_network_firewall || warn "Network Firewall provisioning failed, continuing..."
    provision_fsx || warn "FSx provisioning failed, continuing..."
    provision_transfer || warn "Transfer provisioning failed, continuing..."
    provision_sagemaker || warn "SageMaker provisioning failed, continuing..."
    provision_dax || warn "DAX provisioning failed, continuing..."
    provision_elasticbeanstalk || warn "Elastic Beanstalk provisioning failed, continuing..."
    provision_datasync || warn "DataSync provisioning failed, continuing..."

    print_summary
}

main
