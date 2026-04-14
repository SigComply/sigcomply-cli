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
	ListBucketsFunc                        func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryptionFunc                func(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioningFunc                func(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetPublicAccessBlockFunc               func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketPolicyFunc                    func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketLoggingFunc                   func(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	GetBucketLifecycleConfigurationFunc    func(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
	GetObjectLockConfigurationFunc         func(ctx context.Context, params *s3.GetObjectLockConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	GetBucketReplicationFunc               func(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error)
	GetBucketNotificationConfigurationFunc func(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error)
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

func (m *MockS3Client) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if m.GetBucketPolicyFunc != nil {
		return m.GetBucketPolicyFunc(ctx, params, optFns...)
	}
	// Default: no bucket policy
	return nil, errors.New("NoSuchBucketPolicy")
}

func (m *MockS3Client) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if m.GetBucketLoggingFunc != nil {
		return m.GetBucketLoggingFunc(ctx, params, optFns...)
	}
	// Default: no logging
	return &s3.GetBucketLoggingOutput{}, nil
}

func (m *MockS3Client) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	if m.GetBucketLifecycleConfigurationFunc != nil {
		return m.GetBucketLifecycleConfigurationFunc(ctx, params, optFns...)
	}
	// Default: no lifecycle configuration
	return nil, errors.New("NoSuchLifecycleConfiguration")
}

func (m *MockS3Client) GetObjectLockConfiguration(ctx context.Context, params *s3.GetObjectLockConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	if m.GetObjectLockConfigurationFunc != nil {
		return m.GetObjectLockConfigurationFunc(ctx, params, optFns...)
	}
	// Default: no object lock
	return nil, errors.New("ObjectLockConfigurationNotFoundError")
}

func (m *MockS3Client) GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error) {
	if m.GetBucketReplicationFunc != nil {
		return m.GetBucketReplicationFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ReplicationConfigurationNotFoundError")
}

func (m *MockS3Client) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	if m.GetBucketNotificationConfigurationFunc != nil {
		return m.GetBucketNotificationConfigurationFunc(ctx, params, optFns...)
	}
	return &s3.GetBucketNotificationConfigurationOutput{}, nil
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
	assert.False(t, buckets[0].HasSSLEnforcement)
	assert.False(t, buckets[0].BucketPolicyExists)
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

// --- Bucket policy / SSL enforcement tests ---

func TestS3Collector_BucketPolicy_SSLEnforcement(t *testing.T) {
	sslPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "DenyInsecureTransport",
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::secure-bucket/*",
			"Condition": {
				"Bool": {"aws:SecureTransport": "false"}
			}
		}]
	}`

	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String("secure-bucket")},
					{Name: aws.String("no-policy-bucket")},
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
			return &s3.GetPublicAccessBlockOutput{}, nil
		},
		GetBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
			if *params.Bucket == "secure-bucket" {
				return &s3.GetBucketPolicyOutput{
					Policy: aws.String(sslPolicy),
				}, nil
			}
			return nil, errors.New("NoSuchBucketPolicy")
		},
	}

	collector := &S3Collector{client: mockS3}
	buckets, err := collector.CollectBuckets(context.Background())

	require.NoError(t, err)
	require.Len(t, buckets, 2)

	var secureBucket, noPolicyBucket *S3Bucket
	for i := range buckets {
		if buckets[i].Name == "secure-bucket" {
			secureBucket = &buckets[i]
		}
		if buckets[i].Name == "no-policy-bucket" {
			noPolicyBucket = &buckets[i]
		}
	}

	require.NotNil(t, secureBucket)
	assert.True(t, secureBucket.BucketPolicyExists)
	assert.True(t, secureBucket.HasSSLEnforcement)

	require.NotNil(t, noPolicyBucket)
	assert.False(t, noPolicyBucket.BucketPolicyExists)
	assert.False(t, noPolicyBucket.HasSSLEnforcement)
}

func TestS3Collector_BucketPolicy_NonSSLPolicy(t *testing.T) {
	// Policy exists but doesn't enforce SSL
	nonSSLPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::public-bucket/*"
		}]
	}`

	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("public-bucket")}},
			}, nil
		},
		GetBucketEncryptionFunc: func(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
			return nil, errors.New("no encryption")
		},
		GetBucketVersioningFunc: func(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			return &s3.GetBucketVersioningOutput{}, nil
		},
		GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			return &s3.GetPublicAccessBlockOutput{}, nil
		},
		GetBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
			return &s3.GetBucketPolicyOutput{Policy: aws.String(nonSSLPolicy)}, nil
		},
	}

	collector := &S3Collector{client: mockS3}
	buckets, err := collector.CollectBuckets(context.Background())

	require.NoError(t, err)
	require.Len(t, buckets, 1)
	assert.True(t, buckets[0].BucketPolicyExists)
	assert.False(t, buckets[0].HasSSLEnforcement, "policy without SecureTransport should not be detected as SSL enforcement")
}

func TestS3Collector_BucketPolicy_Error_FailSafe(t *testing.T) {
	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("my-bucket")}},
			}, nil
		},
		GetBucketEncryptionFunc: func(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
			return nil, errors.New("denied")
		},
		GetBucketVersioningFunc: func(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			return &s3.GetBucketVersioningOutput{}, nil
		},
		GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			return &s3.GetPublicAccessBlockOutput{}, nil
		},
		GetBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := &S3Collector{client: mockS3}
	buckets, err := collector.CollectBuckets(context.Background())

	require.NoError(t, err, "should not fail when bucket policy query fails")
	require.Len(t, buckets, 1)
	assert.False(t, buckets[0].BucketPolicyExists)
	assert.False(t, buckets[0].HasSSLEnforcement)
}

// --- Access logging tests ---

func TestS3Collector_enrichLogging(t *testing.T) {
	tests := []struct {
		name             string
		loggingOutput    *s3.GetBucketLoggingOutput
		loggingErr       error
		wantEnabled      bool
		wantTargetBucket string
	}{
		{
			name: "logging enabled with target bucket",
			loggingOutput: &s3.GetBucketLoggingOutput{
				LoggingEnabled: &types.LoggingEnabled{
					TargetBucket: aws.String("log-bucket"),
					TargetPrefix: aws.String("logs/"),
				},
			},
			wantEnabled:      true,
			wantTargetBucket: "log-bucket",
		},
		{
			name:          "logging not configured",
			loggingOutput: &s3.GetBucketLoggingOutput{},
			wantEnabled:   false,
		},
		{
			name:        "logging query fails (fail-safe)",
			loggingErr:  errors.New("access denied"),
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockS3Client{
				GetBucketLoggingFunc: func(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
					if tt.loggingErr != nil {
						return nil, tt.loggingErr
					}
					return tt.loggingOutput, nil
				},
			}

			collector := &S3Collector{client: mock}
			bucket := &S3Bucket{Name: "test-bucket"}
			collector.enrichLogging(context.Background(), bucket)

			assert.Equal(t, tt.wantEnabled, bucket.LoggingEnabled)
			assert.Equal(t, tt.wantTargetBucket, bucket.LoggingTargetBucket)
		})
	}
}

func TestS3Collector_enrichObjectLock(t *testing.T) {
	tests := []struct {
		name     string
		output   *s3.GetObjectLockConfigurationOutput
		err      error
		wantLock bool
	}{
		{
			name: "object lock enabled",
			output: &s3.GetObjectLockConfigurationOutput{
				ObjectLockConfiguration: &types.ObjectLockConfiguration{
					ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				},
			},
			wantLock: true,
		},
		{
			name:     "object lock not configured",
			output:   &s3.GetObjectLockConfigurationOutput{},
			wantLock: false,
		},
		{
			name:     "object lock query fails (fail-safe)",
			err:      errors.New("ObjectLockConfigurationNotFoundError"),
			wantLock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockS3Client{
				GetObjectLockConfigurationFunc: func(ctx context.Context, params *s3.GetObjectLockConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
					if tt.err != nil {
						return nil, tt.err
					}
					return tt.output, nil
				},
			}

			collector := &S3Collector{client: mock}
			bucket := &S3Bucket{Name: "test-bucket"}
			collector.enrichObjectLock(context.Background(), bucket)

			assert.Equal(t, tt.wantLock, bucket.ObjectLockEnabled)
		})
	}
}
