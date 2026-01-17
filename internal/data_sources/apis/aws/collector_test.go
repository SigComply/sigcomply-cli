package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSTSClient is a mock implementation of STSClient for testing.
type MockSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *MockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.GetCallerIdentityFunc(ctx, params, optFns...)
}

func TestCollector_GetAccountID(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *sts.GetCallerIdentityOutput
		mockError     error
		wantAccountID string
		wantError     bool
	}{
		{
			name: "successful account ID retrieval",
			mockResponse: &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
				UserId:  aws.String("AIDAEXAMPLEID"),
			},
			wantAccountID: "123456789012",
			wantError:     false,
		},
		{
			name:      "STS API error",
			mockError: errors.New("access denied"),
			wantError: true,
		},
		{
			name: "nil account in response",
			mockResponse: &sts.GetCallerIdentityOutput{
				Account: nil,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSTS := &MockSTSClient{
				GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			collector := &Collector{
				stsClient: mockSTS,
			}

			accountID, err := collector.GetAccountID(context.Background())

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantAccountID, accountID)
			}
		})
	}
}

func TestCollector_New(t *testing.T) {
	// This test verifies the constructor doesn't panic
	// Actual AWS credential loading is tested in integration tests
	collector := New()
	assert.NotNil(t, collector)
}

func TestCollector_WithRegion(t *testing.T) {
	collector := New()

	// Chain method should return the collector
	result := collector.WithRegion("us-west-2")
	assert.Equal(t, collector, result)
	assert.Equal(t, "us-west-2", collector.region)
}

func TestCollector_Status(t *testing.T) {
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
			}, nil
		},
	}

	collector := &Collector{
		stsClient: mockSTS,
		region:    "us-east-1",
	}

	status := collector.Status(context.Background())

	assert.True(t, status.Connected)
	assert.Equal(t, "123456789012", status.AccountID)
	assert.Equal(t, "us-east-1", status.Region)
}

func TestCollector_Status_NotConnected(t *testing.T) {
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return nil, errors.New("no credentials")
		},
	}

	collector := &Collector{
		stsClient: mockSTS,
	}

	status := collector.Status(context.Background())

	assert.False(t, status.Connected)
	assert.Contains(t, status.Error, "no credentials")
}

func TestCollector_Collect_FailSafe(t *testing.T) {
	// Test that collection continues even when one service fails
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
			}, nil
		},
	}

	// IAM fails, but S3 and CloudTrail should still work
	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return nil, errors.New("IAM access denied")
		},
	}

	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []s3types.Bucket{
					{Name: aws.String("test-bucket")},
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
	}

	mockCloudTrail := &MockCloudTrailClient{
		DescribeTrailsFunc: func(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
			return &cloudtrail.DescribeTrailsOutput{
				TrailList: []cttypes.Trail{
					{Name: aws.String("test-trail"), TrailARN: aws.String("arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail")},
				},
			}, nil
		},
		GetTrailStatusFunc: func(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
			return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true)}, nil
		},
	}

	collector := &Collector{
		stsClient:        mockSTS,
		iamClient:        mockIAM,
		s3Client:         mockS3,
		cloudtrailClient: mockCloudTrail,
	}

	result, err := collector.Collect(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasErrors(), "should have errors from IAM failure")
	assert.Len(t, result.Errors, 1)
	assert.Equal(t, "iam", result.Errors[0].Service)

	// Should still have evidence from S3 and CloudTrail
	assert.Len(t, result.Evidence, 2, "should have evidence from S3 and CloudTrail")
}

func TestCollectionResult_HasErrors(t *testing.T) {
	result := &CollectionResult{}
	assert.False(t, result.HasErrors())

	result.Errors = append(result.Errors, CollectionError{Service: "test", Error: "error"})
	assert.True(t, result.HasErrors())
}
