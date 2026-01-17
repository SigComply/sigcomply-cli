package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

// S3Client defines the interface for S3 operations we use.
type S3Client interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

// S3Bucket represents an S3 bucket with security configuration.
type S3Bucket struct {
	Name                string    `json:"name"`
	ARN                 string    `json:"arn"`
	CreationDate        time.Time `json:"creation_date,omitempty"`
	EncryptionEnabled   bool      `json:"encryption_enabled"`
	EncryptionAlgorithm string    `json:"encryption_algorithm,omitempty"`
	EncryptionKeyID     string    `json:"encryption_key_id,omitempty"`
	VersioningEnabled   bool      `json:"versioning_enabled"`
	PublicAccessBlocked bool      `json:"public_access_blocked"`
}

// ToEvidence converts an S3Bucket to an Evidence struct.
func (b *S3Bucket) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(b) //nolint:errcheck // Marshal of known struct won't fail
	ev := evidence.New("aws", "aws:s3:bucket", b.ARN, data)
	ev.Metadata = evidence.Metadata{
		AccountID: accountID,
	}
	return ev
}

// S3Collector collects S3 bucket data.
type S3Collector struct {
	client S3Client
}

// NewS3Collector creates a new S3 collector.
func NewS3Collector(client S3Client) *S3Collector {
	return &S3Collector{client: client}
}

// CollectBuckets retrieves all S3 buckets with their security configuration.
func (c *S3Collector) CollectBuckets(ctx context.Context) ([]S3Bucket, error) {
	output, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %w", err)
	}

	buckets := make([]S3Bucket, 0, len(output.Buckets))
	for i := range output.Buckets {
		b := &output.Buckets[i]
		bucket := S3Bucket{
			Name: aws.ToString(b.Name),
			ARN:  fmt.Sprintf("arn:aws:s3:::%s", aws.ToString(b.Name)),
		}

		if b.CreationDate != nil {
			bucket.CreationDate = *b.CreationDate
		}

		// Get encryption configuration
		c.enrichEncryption(ctx, &bucket)

		// Get versioning status
		c.enrichVersioning(ctx, &bucket)

		// Get public access block
		c.enrichPublicAccessBlock(ctx, &bucket)

		buckets = append(buckets, bucket)
	}

	return buckets, nil
}

// enrichEncryption adds encryption information to a bucket.
func (c *S3Collector) enrichEncryption(ctx context.Context, bucket *S3Bucket) {
	output, err := c.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucket.Name),
	})
	if err != nil {
		// No encryption configured or access denied - fail-safe approach
		bucket.EncryptionEnabled = false
		return
	}

	if output.ServerSideEncryptionConfiguration != nil {
		for _, rule := range output.ServerSideEncryptionConfiguration.Rules {
			if rule.ApplyServerSideEncryptionByDefault != nil {
				bucket.EncryptionEnabled = true
				bucket.EncryptionAlgorithm = string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
				if rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID != nil {
					bucket.EncryptionKeyID = aws.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
				}
				break
			}
		}
	}
}

// enrichVersioning adds versioning information to a bucket.
func (c *S3Collector) enrichVersioning(ctx context.Context, bucket *S3Bucket) {
	output, err := c.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket.Name),
	})
	if err != nil {
		// Access denied or other error - fail-safe approach
		bucket.VersioningEnabled = false
		return
	}

	bucket.VersioningEnabled = output.Status == types.BucketVersioningStatusEnabled
}

// enrichPublicAccessBlock adds public access block information to a bucket.
func (c *S3Collector) enrichPublicAccessBlock(ctx context.Context, bucket *S3Bucket) {
	output, err := c.client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket.Name),
	})
	if err != nil {
		// No public access block configured or access denied
		bucket.PublicAccessBlocked = false
		return
	}

	if output.PublicAccessBlockConfiguration != nil {
		cfg := output.PublicAccessBlockConfiguration
		bucket.PublicAccessBlocked = aws.ToBool(cfg.BlockPublicAcls) &&
			aws.ToBool(cfg.BlockPublicPolicy) &&
			aws.ToBool(cfg.IgnorePublicAcls) &&
			aws.ToBool(cfg.RestrictPublicBuckets)
	}
}

// CollectEvidence collects S3 buckets as evidence.
func (c *S3Collector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	buckets, err := c.CollectBuckets(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(buckets))
	for i := range buckets {
		evidenceList = append(evidenceList, buckets[i].ToEvidence(accountID))
	}

	return evidenceList, nil
}
