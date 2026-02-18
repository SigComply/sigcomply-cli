package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testEncryptedBucket = "encrypted-bucket"

// MockS3Client is a mock implementation of S3Client for testing.
type MockS3Client struct {
	ListBucketsFunc               func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryptionFunc       func(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioningFunc       func(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetPublicAccessBlockFunc      func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

func (m *MockS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return m.ListBucketsFunc(ctx, params, optFns...)
}

func (m *MockS3Client) GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return m.GetBucketEncryptionFunc(ctx, params, optFns...)
}

func (m *MockS3Client) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return m.GetBucketVersioningFunc(ctx, params, optFns...)
}

func (m *MockS3Client) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return m.GetPublicAccessBlockFunc(ctx, params, optFns...)
}

func TestS3Collector_CollectBuckets(t *testing.T) {
	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String(testEncryptedBucket)},
					{Name: aws.String("unencrypted-bucket")},
				},
			}, nil
		},
		GetBucketEncryptionFunc: func(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
			if *params.Bucket == testEncryptedBucket {
				return &s3.GetBucketEncryptionOutput{
					ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
						Rules: []types.ServerSideEncryptionRule{
							{
								ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
									SSEAlgorithm: types.ServerSideEncryptionAes256,
								},
							},
						},
					},
				}, nil
			}
			// Return error for unencrypted bucket (no encryption configured)
			return nil, &types.NoSuchBucket{Message: aws.String("no encryption")}
		},
		GetBucketVersioningFunc: func(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			if *params.Bucket == testEncryptedBucket {
				return &s3.GetBucketVersioningOutput{
					Status: types.BucketVersioningStatusEnabled,
				}, nil
			}
			return &s3.GetBucketVersioningOutput{}, nil
		},
		GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			return &s3.GetPublicAccessBlockOutput{
				PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
					BlockPublicAcls:       aws.Bool(true),
					BlockPublicPolicy:     aws.Bool(true),
					IgnorePublicAcls:      aws.Bool(true),
					RestrictPublicBuckets: aws.Bool(true),
				},
			}, nil
		},
	}

	collector := &S3Collector{client: mockS3}
	buckets, err := collector.CollectBuckets(context.Background())

	require.NoError(t, err)
	assert.Len(t, buckets, 2)

	// Find encrypted bucket
	var encryptedBucket, unencryptedBucket *S3Bucket
	for i := range buckets {
		if buckets[i].Name == testEncryptedBucket {
			encryptedBucket = &buckets[i]
		}
		if buckets[i].Name == "unencrypted-bucket" {
			unencryptedBucket = &buckets[i]
		}
	}

	require.NotNil(t, encryptedBucket)
	assert.True(t, encryptedBucket.EncryptionEnabled)
	assert.Equal(t, "AES256", encryptedBucket.EncryptionAlgorithm)
	assert.True(t, encryptedBucket.VersioningEnabled)

	require.NotNil(t, unencryptedBucket)
	assert.False(t, unencryptedBucket.EncryptionEnabled)
}

func TestS3Collector_CollectBuckets_NoBuckets(t *testing.T) {
	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{Buckets: []types.Bucket{}}, nil
		},
	}

	collector := &S3Collector{client: mockS3}
	buckets, err := collector.CollectBuckets(context.Background())

	require.NoError(t, err)
	assert.Empty(t, buckets)
}

func TestS3Collector_CollectBuckets_APIError(t *testing.T) {
	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := &S3Collector{client: mockS3}
	_, err := collector.CollectBuckets(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// --- Negative tests ---

func TestS3Collector_CollectBuckets_VersioningError(t *testing.T) {
	// GetBucketVersioning fails for a bucket — should default to VersioningEnabled=false
	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String("my-bucket")},
				},
			}, nil
		},
		GetBucketEncryptionFunc: func(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
			return nil, errors.New("no encryption")
		},
		GetBucketVersioningFunc: func(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			return nil, errors.New("access denied")
		},
		GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			return &s3.GetPublicAccessBlockOutput{}, nil
		},
	}

	collector := &S3Collector{client: mockS3}
	buckets, err := collector.CollectBuckets(context.Background())

	require.NoError(t, err, "should not fail when versioning query fails")
	require.Len(t, buckets, 1)
	assert.False(t, buckets[0].VersioningEnabled, "should default to false on error")
}

func TestS3Collector_CollectBuckets_PublicAccessBlockError(t *testing.T) {
	// GetPublicAccessBlock fails — should default to PublicAccessBlocked=false
	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String("my-bucket")},
				},
			}, nil
		},
		GetBucketEncryptionFunc: func(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
			return nil, errors.New("no encryption")
		},
		GetBucketVersioningFunc: func(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			return &s3.GetBucketVersioningOutput{}, nil
		},
		GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := &S3Collector{client: mockS3}
	buckets, err := collector.CollectBuckets(context.Background())

	require.NoError(t, err, "should not fail when public access block query fails")
	require.Len(t, buckets, 1)
	assert.False(t, buckets[0].PublicAccessBlocked, "should default to false on error")
}

func TestS3Collector_CollectBuckets_AllEnrichmentErrors(t *testing.T) {
	// All enrichment calls fail — bucket should still be collected with safe defaults
	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String("my-bucket")},
				},
			}, nil
		},
		GetBucketEncryptionFunc: func(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
			return nil, errors.New("denied")
		},
		GetBucketVersioningFunc: func(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			return nil, errors.New("denied")
		},
		GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			return nil, errors.New("denied")
		},
	}

	collector := &S3Collector{client: mockS3}
	buckets, err := collector.CollectBuckets(context.Background())

	require.NoError(t, err)
	require.Len(t, buckets, 1)
	assert.Equal(t, "my-bucket", buckets[0].Name)
	assert.False(t, buckets[0].EncryptionEnabled)
	assert.False(t, buckets[0].VersioningEnabled)
	assert.False(t, buckets[0].PublicAccessBlocked)
}

func TestS3Collector_ToEvidence(t *testing.T) {
	bucket := S3Bucket{
		Name:                "my-bucket",
		ARN:                 "arn:aws:s3:::my-bucket",
		EncryptionEnabled:   true,
		EncryptionAlgorithm: "AES256",
		VersioningEnabled:   true,
		PublicAccessBlocked: true,
	}

	evidence := bucket.ToEvidence("123456789012")

	assert.Equal(t, "aws", evidence.Collector)
	assert.Equal(t, "aws:s3:bucket", evidence.ResourceType)
	assert.Equal(t, "arn:aws:s3:::my-bucket", evidence.ResourceID)
	assert.NotEmpty(t, evidence.Hash)
}
