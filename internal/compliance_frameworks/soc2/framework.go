// Package soc2 provides the SOC 2 compliance framework implementation.
package soc2

import (
	_ "embed"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
)

// CC6.1 - Logical Access Security
//
//go:embed policies/cc6_1_mfa.rego
var cc61MFAPolicy string

//go:embed policies/cc6_1_github_mfa.rego
var cc61GitHubMFAPolicy string

//go:embed policies/cc6_1_root_security.rego
var cc61RootSecurityPolicy string

//go:embed policies/cc6_1_password_policy.rego
var cc61PasswordPolicyPolicy string

//go:embed policies/cc6_1_key_rotation.rego
var cc61KeyRotationPolicy string

//go:embed policies/cc6_1_kms_rotation.rego
var cc61KMSRotationPolicy string

//go:embed policies/cc6_1_access_key_rotation.rego
var cc61AccessKeyRotationPolicy string

//go:embed policies/cc6_1_ec2_imdsv2.rego
var cc61EC2IMDSv2Policy string

//go:embed policies/cc6_1_secrets_rotation.rego
var cc61SecretsRotationPolicy string

//go:embed policies/cc6_1_ssm_session_manager.rego
var cc61SSMSessionManagerPolicy string

// CC6.2 - Data Protection
//
//go:embed policies/cc6_2_encryption.rego
var cc62EncryptionPolicy string

//go:embed policies/cc6_2_ebs_encryption.rego
var cc62EBSEncryptionPolicy string

//go:embed policies/cc6_2_rds_encryption.rego
var cc62RDSEncryptionPolicy string

//go:embed policies/cc6_2_s3_public_access.rego
var cc62S3PublicAccessPolicy string

//go:embed policies/cc6_2_gcp_storage_encryption.rego
var cc62GCPStorageEncryptionPolicy string

//go:embed policies/cc6_2_gcp_disk_encryption.rego
var cc62GCPDiskEncryptionPolicy string

//go:embed policies/cc6_2_gcp_sql_encryption.rego
var cc62GCPSQLEncryptionPolicy string

//go:embed policies/cc6_2_gcp_storage_public.rego
var cc62GCPStoragePublicPolicy string

//go:embed policies/cc6_2_cloudtrail_encryption.rego
var cc62CloudTrailEncryptionPolicy string

//go:embed policies/cc6_2_s3_account_public_access.rego
var cc62S3AccountPublicAccessPolicy string

//go:embed policies/cc6_2_dynamodb_encryption.rego
var cc62DynamoDBEncryptionPolicy string

// CC6.3 - Access Removal
//
//go:embed policies/cc6_3_unused_credentials.rego
var cc63UnusedCredentialsPolicy string

//go:embed policies/cc6_3_overly_permissive.rego
var cc63OverlyPermissivePolicy string

//go:embed policies/cc6_3_unused_credentials_aws.rego
var cc63UnusedCredentialsAWSPolicy string

//go:embed policies/cc6_3_overly_permissive_aws.rego
var cc63OverlyPermissiveAWSPolicy string

// CC6.6 - Network Security
//
//go:embed policies/cc6_6_open_ports.rego
var cc66OpenPortsPolicy string

//go:embed policies/cc6_6_rds_public.rego
var cc66RDSPublicPolicy string

//go:embed policies/cc6_6_vpc_flow_logs.rego
var cc66VPCFlowLogsPolicy string

//go:embed policies/cc6_6_waf_enabled.rego
var cc66WAFEnabledPolicy string

// CC6.7 - Data Transmission Security
//
//go:embed policies/cc6_7_s3_https.rego
var cc67S3HTTPSPolicy string

//go:embed policies/cc6_7_rds_ssl.rego
var cc67RDSSSLPolicy string

//go:embed policies/cc6_7_acm_expiry.rego
var cc67ACMExpiryPolicy string

//go:embed policies/cc6_7_cloudfront_https.rego
var cc67CloudFrontHTTPSPolicy string

// CC6.8 - Malicious Software Prevention
//
//go:embed policies/cc6_8_ecr_scanning.rego
var cc68ECRScanningPolicy string

//go:embed policies/cc6_8_lambda_security.rego
var cc68LambdaSecurityPolicy string

//go:embed policies/cc6_8_ecs_security.rego
var cc68ECSSecurityPolicy string

//go:embed policies/cc6_8_eks_security.rego
var cc68EKSSecurityPolicy string

// CC7.1 - Monitoring and Detection
//
//go:embed policies/cc7_1_logging.rego
var cc71LoggingPolicy string

//go:embed policies/cc7_1_log_retention.rego
var cc71LogRetentionPolicy string

//go:embed policies/cc7_1_s3_access_logging.rego
var cc71S3AccessLoggingPolicy string

//go:embed policies/cc7_1_cloudwatch_alarms.rego
var cc71CloudWatchAlarmsPolicy string

// CC7.2 - Security Event Monitoring
//
//go:embed policies/cc7_2_guardduty.rego
var cc72GuardDutyPolicy string

//go:embed policies/cc7_2_security_hub.rego
var cc72SecurityHubPolicy string

// CC8.1 - Change Management
//
//go:embed policies/cc8_1_config_enabled.rego
var cc81ConfigEnabledPolicy string

// A1.2 - Recovery and Continuity
//
//go:embed policies/a1_2_rds_backup.rego
var a12RDSBackupPolicy string

//go:embed policies/a1_2_s3_versioning.rego
var a12S3VersioningPolicy string

//go:embed policies/a1_2_rds_multi_az.rego
var a12RDSMultiAZPolicy string

//go:embed policies/a1_2_rds_deletion_protection.rego
var a12RDSDeletionProtectionPolicy string

//go:embed policies/a1_2_dynamodb_pitr.rego
var a12DynamoDBPITRPolicy string

// C1.1 - Confidentiality Protection
//
//go:embed policies/c1_1_encryption_coverage.rego
var c11EncryptionCoveragePolicy string

//go:embed policies/c1_1_macie_enabled.rego
var c11MacieEnabledPolicy string

// Framework implements the engine.Framework interface for SOC 2.
type Framework struct{}

// New creates a new SOC 2 framework instance.
func New() *Framework {
	return &Framework{}
}

// Name returns the framework identifier.
func (f *Framework) Name() string {
	return "soc2"
}

// DisplayName returns the human-readable name.
func (f *Framework) DisplayName() string {
	return "SOC 2 Type II"
}

// Version returns the framework version.
func (f *Framework) Version() string {
	return "2017"
}

// Description returns a brief description of the framework.
func (f *Framework) Description() string {
	return "AICPA Trust Services Criteria for SOC 2 Type II compliance"
}

// Controls returns all controls defined in this framework.
func (f *Framework) Controls() []engine.Control {
	soc2Controls := GetControls()
	result := make([]engine.Control, len(soc2Controls))
	for i, c := range soc2Controls {
		result[i] = engine.Control{
			ID:          c.ID,
			Name:        c.Name,
			Description: c.Description,
			Category:    c.Category,
			Severity:    c.Severity,
		}
	}
	return result
}

// GetControl returns a specific control by ID.
func (f *Framework) GetControl(id string) *engine.Control {
	c := GetControl(id)
	if c == nil {
		return nil
	}
	return &engine.Control{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		Category:    c.Category,
		Severity:    c.Severity,
	}
}

// Policies returns all Rego policy sources for this framework.
func (f *Framework) Policies() []engine.PolicySource {
	return []engine.PolicySource{
		// CC6.1 - Logical Access Security
		{Name: "cc6_1_mfa", Source: cc61MFAPolicy},
		{Name: "cc6_1_github_mfa", Source: cc61GitHubMFAPolicy},
		{Name: "cc6_1_root_security", Source: cc61RootSecurityPolicy},
		{Name: "cc6_1_password_policy", Source: cc61PasswordPolicyPolicy},
		{Name: "cc6_1_key_rotation", Source: cc61KeyRotationPolicy},
		{Name: "cc6_1_kms_rotation", Source: cc61KMSRotationPolicy},
		{Name: "cc6_1_access_key_rotation", Source: cc61AccessKeyRotationPolicy},
		{Name: "cc6_1_ec2_imdsv2", Source: cc61EC2IMDSv2Policy},
		{Name: "cc6_1_secrets_rotation", Source: cc61SecretsRotationPolicy},
		{Name: "cc6_1_ssm_session_manager", Source: cc61SSMSessionManagerPolicy},

		// CC6.2 - Data Protection
		{Name: "cc6_2_encryption", Source: cc62EncryptionPolicy},
		{Name: "cc6_2_ebs_encryption", Source: cc62EBSEncryptionPolicy},
		{Name: "cc6_2_rds_encryption", Source: cc62RDSEncryptionPolicy},
		{Name: "cc6_2_s3_public_access", Source: cc62S3PublicAccessPolicy},
		{Name: "cc6_2_gcp_storage_encryption", Source: cc62GCPStorageEncryptionPolicy},
		{Name: "cc6_2_gcp_disk_encryption", Source: cc62GCPDiskEncryptionPolicy},
		{Name: "cc6_2_gcp_sql_encryption", Source: cc62GCPSQLEncryptionPolicy},
		{Name: "cc6_2_gcp_storage_public", Source: cc62GCPStoragePublicPolicy},
		{Name: "cc6_2_cloudtrail_encryption", Source: cc62CloudTrailEncryptionPolicy},
		{Name: "cc6_2_s3_account_public_access", Source: cc62S3AccountPublicAccessPolicy},
		{Name: "cc6_2_dynamodb_encryption", Source: cc62DynamoDBEncryptionPolicy},

		// CC6.3 - Access Removal
		{Name: "cc6_3_unused_credentials", Source: cc63UnusedCredentialsPolicy},
		{Name: "cc6_3_overly_permissive", Source: cc63OverlyPermissivePolicy},
		{Name: "cc6_3_unused_credentials_aws", Source: cc63UnusedCredentialsAWSPolicy},
		{Name: "cc6_3_overly_permissive_aws", Source: cc63OverlyPermissiveAWSPolicy},

		// CC6.6 - Network Security
		{Name: "cc6_6_open_ports", Source: cc66OpenPortsPolicy},
		{Name: "cc6_6_rds_public", Source: cc66RDSPublicPolicy},
		{Name: "cc6_6_vpc_flow_logs", Source: cc66VPCFlowLogsPolicy},
		{Name: "cc6_6_waf_enabled", Source: cc66WAFEnabledPolicy},

		// CC6.7 - Data Transmission Security
		{Name: "cc6_7_s3_https", Source: cc67S3HTTPSPolicy},
		{Name: "cc6_7_rds_ssl", Source: cc67RDSSSLPolicy},
		{Name: "cc6_7_acm_expiry", Source: cc67ACMExpiryPolicy},
		{Name: "cc6_7_cloudfront_https", Source: cc67CloudFrontHTTPSPolicy},

		// CC6.8 - Malicious Software Prevention
		{Name: "cc6_8_ecr_scanning", Source: cc68ECRScanningPolicy},
		{Name: "cc6_8_lambda_security", Source: cc68LambdaSecurityPolicy},
		{Name: "cc6_8_ecs_security", Source: cc68ECSSecurityPolicy},
		{Name: "cc6_8_eks_security", Source: cc68EKSSecurityPolicy},

		// CC7.1 - Monitoring and Detection
		{Name: "cc7_1_logging", Source: cc71LoggingPolicy},
		{Name: "cc7_1_log_retention", Source: cc71LogRetentionPolicy},
		{Name: "cc7_1_s3_access_logging", Source: cc71S3AccessLoggingPolicy},
		{Name: "cc7_1_cloudwatch_alarms", Source: cc71CloudWatchAlarmsPolicy},

		// CC7.2 - Security Event Monitoring
		{Name: "cc7_2_guardduty", Source: cc72GuardDutyPolicy},
		{Name: "cc7_2_security_hub", Source: cc72SecurityHubPolicy},

		// CC8.1 - Change Management
		{Name: "cc8_1_config_enabled", Source: cc81ConfigEnabledPolicy},

		// A1.2 - Recovery and Continuity
		{Name: "a1_2_rds_backup", Source: a12RDSBackupPolicy},
		{Name: "a1_2_s3_versioning", Source: a12S3VersioningPolicy},
		{Name: "a1_2_rds_multi_az", Source: a12RDSMultiAZPolicy},
		{Name: "a1_2_rds_deletion_protection", Source: a12RDSDeletionProtectionPolicy},
		{Name: "a1_2_dynamodb_pitr", Source: a12DynamoDBPITRPolicy},

		// C1.1 - Confidentiality Protection
		{Name: "c1_1_encryption_coverage", Source: c11EncryptionCoveragePolicy},
		{Name: "c1_1_macie_enabled", Source: c11MacieEnabledPolicy},
	}
}

// Register registers the SOC 2 framework with the default registry.
func Register() error {
	return engine.RegisterFramework(New())
}

// Ensure Framework implements the Framework interface.
var _ engine.Framework = (*Framework)(nil)
