// Package aws provides evidence collection from AWS services.
package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// STSClient defines the interface for STS operations we use.
type STSClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// CollectorStatus represents the current state of the AWS collector.
type CollectorStatus struct {
	Connected bool   `json:"connected"`
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
	Error     string `json:"error,omitempty"`
}

// CollectionResult represents the result of collecting evidence from AWS.
type CollectionResult struct {
	Evidence []evidence.Evidence `json:"evidence"`
	Errors   []CollectionError   `json:"errors,omitempty"`
}

// CollectionError represents an error during collection from a specific service.
type CollectionError struct {
	Service string `json:"service"`
	Error   string `json:"error"`
}

// HasErrors returns true if there were any collection errors.
func (r *CollectionResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// Collector gathers evidence from AWS services.
type Collector struct {
	stsClient          STSClient
	iamClient          IAMClient
	accountClient      AccountClient
	s3Client           S3Client
	cloudtrailClient   CloudTrailClient
	ec2Client          EC2Client
	rdsClient          RDSClient
	kmsClient          KMSClient
	guarddutyClient    GuardDutyClient
	cloudwatchClient   CloudWatchLogsClient
	ecrClient          ECRClient
	configClient       ConfigServiceClient
	region             string
	accountID          string // Cached after first retrieval
	cfg                aws.Config
}

// New creates a new AWS Collector with auto-detected credentials.
func New() *Collector {
	return &Collector{}
}

// WithRegion sets the AWS region for the collector.
func (c *Collector) WithRegion(region string) *Collector {
	c.region = region
	return c
}

// Init initializes all AWS service clients with auto-detected credentials.
func (c *Collector) Init(ctx context.Context) error {
	opts := []func(*awsconfig.LoadOptions) error{}

	if c.region != "" {
		opts = append(opts, awsconfig.WithRegion(c.region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	c.cfg = cfg

	// Store the resolved region
	if c.region == "" {
		c.region = cfg.Region
	}

	// Initialize all service clients
	c.stsClient = sts.NewFromConfig(cfg)
	c.iamClient = iam.NewFromConfig(cfg)
	c.accountClient = iam.NewFromConfig(cfg)
	c.s3Client = s3.NewFromConfig(cfg)
	c.cloudtrailClient = cloudtrail.NewFromConfig(cfg)
	c.ec2Client = ec2.NewFromConfig(cfg)
	c.rdsClient = rds.NewFromConfig(cfg)
	c.kmsClient = kms.NewFromConfig(cfg)
	c.guarddutyClient = guardduty.NewFromConfig(cfg)
	c.cloudwatchClient = cloudwatchlogs.NewFromConfig(cfg)
	c.ecrClient = ecr.NewFromConfig(cfg)
	c.configClient = configservice.NewFromConfig(cfg)

	return nil
}

// GetAccountID retrieves the AWS account ID using STS GetCallerIdentity.
func (c *Collector) GetAccountID(ctx context.Context) (string, error) {
	// Return cached value if available
	if c.accountID != "" {
		return c.accountID, nil
	}

	if c.stsClient == nil {
		return "", errors.New("collector not initialized: call Init() first")
	}

	result, err := c.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	if result.Account == nil {
		return "", errors.New("account ID not returned from STS")
	}

	c.accountID = *result.Account
	return c.accountID, nil
}

// Status returns the current connection status of the collector.
// Note: This method intentionally returns nil error even when connection fails,
// because connection failure is a valid status (not an execution error).
func (c *Collector) Status(ctx context.Context) CollectorStatus {
	status := CollectorStatus{
		Region: c.region,
	}

	accountID, err := c.GetAccountID(ctx)
	if err != nil {
		status.Connected = false
		status.Error = err.Error()
		return status
	}

	status.Connected = true
	status.AccountID = accountID
	return status
}

// Region returns the configured region.
func (c *Collector) Region() string {
	return c.region
}

// Collect gathers evidence from all AWS services using fail-safe pattern.
// If one service fails, the others continue and partial results are returned.
func (c *Collector) Collect(ctx context.Context) (*CollectionResult, error) {
	accountID, err := c.GetAccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get account ID: %w", err)
	}

	result := &CollectionResult{
		Evidence: []evidence.Evidence{},
		Errors:   []CollectionError{},
	}

	// Collect IAM users
	c.collectIAM(ctx, accountID, result)

	// Collect account-level IAM data (password policy, root account)
	c.collectAccount(ctx, accountID, result)

	// Collect S3 buckets
	c.collectS3(ctx, accountID, result)

	// Collect CloudTrail trails
	c.collectCloudTrail(ctx, accountID, result)

	// Collect EC2 resources (security groups, VPCs, EBS encryption)
	c.collectEC2(ctx, accountID, result)

	// Collect RDS instances
	c.collectRDS(ctx, accountID, result)

	// Collect KMS keys
	c.collectKMS(ctx, accountID, result)

	// Collect GuardDuty status
	c.collectGuardDuty(ctx, accountID, result)

	// Collect CloudWatch log groups
	c.collectCloudWatch(ctx, accountID, result)

	// Collect ECR repositories
	c.collectECR(ctx, accountID, result)

	// Collect AWS Config status
	c.collectConfig(ctx, accountID, result)

	return result, nil
}

// collectIAM collects IAM user evidence with fail-safe pattern.
func (c *Collector) collectIAM(ctx context.Context, accountID string, result *CollectionResult) {
	iamCollector := NewIAMCollector(c.iamClient)
	ev, err := iamCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "iam",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectS3 collects S3 bucket evidence with fail-safe pattern.
func (c *Collector) collectS3(ctx context.Context, accountID string, result *CollectionResult) {
	s3Collector := NewS3Collector(c.s3Client)
	ev, err := s3Collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "s3",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectCloudTrail collects CloudTrail evidence with fail-safe pattern.
func (c *Collector) collectCloudTrail(ctx context.Context, accountID string, result *CollectionResult) {
	ctCollector := NewCloudTrailCollector(c.cloudtrailClient)
	ev, err := ctCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "cloudtrail",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectAccount collects account-level IAM evidence with fail-safe pattern.
func (c *Collector) collectAccount(ctx context.Context, accountID string, result *CollectionResult) {
	if c.accountClient == nil {
		return
	}
	accountCollector := NewAccountCollector(c.accountClient)
	ev, err := accountCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "iam-account",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectEC2 collects EC2 evidence with fail-safe pattern.
func (c *Collector) collectEC2(ctx context.Context, accountID string, result *CollectionResult) {
	if c.ec2Client == nil {
		return
	}
	ec2Collector := NewEC2Collector(c.ec2Client, c.region)
	ev, err := ec2Collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "ec2",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectRDS collects RDS evidence with fail-safe pattern.
func (c *Collector) collectRDS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.rdsClient == nil {
		return
	}
	rdsCollector := NewRDSCollector(c.rdsClient)
	ev, err := rdsCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "rds",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectKMS collects KMS evidence with fail-safe pattern.
func (c *Collector) collectKMS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.kmsClient == nil {
		return
	}
	kmsCollector := NewKMSCollector(c.kmsClient)
	ev, err := kmsCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "kms",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectGuardDuty collects GuardDuty evidence with fail-safe pattern.
func (c *Collector) collectGuardDuty(ctx context.Context, accountID string, result *CollectionResult) {
	if c.guarddutyClient == nil {
		return
	}
	gdCollector := NewGuardDutyCollector(c.guarddutyClient, c.region)
	ev, err := gdCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "guardduty",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectCloudWatch collects CloudWatch evidence with fail-safe pattern.
func (c *Collector) collectCloudWatch(ctx context.Context, accountID string, result *CollectionResult) {
	if c.cloudwatchClient == nil {
		return
	}
	cwCollector := NewCloudWatchCollector(c.cloudwatchClient)
	ev, err := cwCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "cloudwatch-logs",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectECR collects ECR evidence with fail-safe pattern.
func (c *Collector) collectECR(ctx context.Context, accountID string, result *CollectionResult) {
	if c.ecrClient == nil {
		return
	}
	ecrCollector := NewECRCollector(c.ecrClient)
	ev, err := ecrCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "ecr",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectConfig collects AWS Config evidence with fail-safe pattern.
func (c *Collector) collectConfig(ctx context.Context, accountID string, result *CollectionResult) {
	if c.configClient == nil {
		return
	}
	configCollector := NewConfigCollector(c.configClient, c.region)
	ev, err := configCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "config",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}
