package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// S3ControlClient defines the interface for S3 Control operations.
type S3ControlClient interface {
	GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

// AccountS3PublicAccess represents the account-level S3 public access block.
type AccountS3PublicAccess struct {
	BlockPublicAcls       bool `json:"block_public_acls"`
	BlockPublicPolicy     bool `json:"block_public_policy"`
	IgnorePublicAcls      bool `json:"ignore_public_acls"`
	RestrictPublicBuckets bool `json:"restrict_public_buckets"`
	AllBlocked            bool `json:"all_blocked"`
}

// ToEvidence converts AccountS3PublicAccess to Evidence.
func (a *AccountS3PublicAccess) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(a) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:s3control::%s:account-public-access", accountID)
	ev := evidence.New("aws", "aws:s3control:account-public-access", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// S3ControlCollector collects account-level S3 access settings.
type S3ControlCollector struct {
	client S3ControlClient
}

// NewS3ControlCollector creates a new S3 Control collector.
func NewS3ControlCollector(client S3ControlClient) *S3ControlCollector {
	return &S3ControlCollector{client: client}
}

// CollectAccountPublicAccess retrieves the account-level public access block.
func (c *S3ControlCollector) CollectAccountPublicAccess(ctx context.Context, accountID string) (*AccountS3PublicAccess, error) {
	config := &AccountS3PublicAccess{}

	output, err := c.client.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: awssdk.String(accountID),
	})
	if err != nil {
		return config, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	if output.PublicAccessBlockConfiguration != nil {
		cfg := output.PublicAccessBlockConfiguration
		config.BlockPublicAcls = awssdk.ToBool(cfg.BlockPublicAcls)
		config.BlockPublicPolicy = awssdk.ToBool(cfg.BlockPublicPolicy)
		config.IgnorePublicAcls = awssdk.ToBool(cfg.IgnorePublicAcls)
		config.RestrictPublicBuckets = awssdk.ToBool(cfg.RestrictPublicBuckets)
		config.AllBlocked = config.BlockPublicAcls && config.BlockPublicPolicy && config.IgnorePublicAcls && config.RestrictPublicBuckets
	}

	return config, nil
}

// CollectEvidence collects account-level S3 public access block as evidence.
func (c *S3ControlCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	config, err := c.CollectAccountPublicAccess(ctx, accountID)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{config.ToEvidence(accountID)}, nil
}
