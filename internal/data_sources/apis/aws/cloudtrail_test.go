package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockCloudTrailClient is a mock implementation of CloudTrailClient for testing.
type MockCloudTrailClient struct {
	DescribeTrailsFunc   func(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatusFunc   func(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

func (m *MockCloudTrailClient) DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return m.DescribeTrailsFunc(ctx, params, optFns...)
}

func (m *MockCloudTrailClient) GetTrailStatus(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return m.GetTrailStatusFunc(ctx, params, optFns...)
}

func TestCloudTrailCollector_CollectTrails(t *testing.T) {
	mockCT := &MockCloudTrailClient{
		DescribeTrailsFunc: func(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
			return &cloudtrail.DescribeTrailsOutput{
				TrailList: []types.Trail{
					{
						Name:                       aws.String("management-trail"),
						TrailARN:                   aws.String("arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail"),
						IsMultiRegionTrail:         aws.Bool(true),
						IsOrganizationTrail:        aws.Bool(false),
						LogFileValidationEnabled:   aws.Bool(true),
						KmsKeyId:                   aws.String("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
						S3BucketName:               aws.String("my-cloudtrail-bucket"),
						IncludeGlobalServiceEvents: aws.Bool(true),
					},
					{
						Name:                       aws.String("regional-trail"),
						TrailARN:                   aws.String("arn:aws:cloudtrail:us-east-1:123456789012:trail/regional-trail"),
						IsMultiRegionTrail:         aws.Bool(false),
						LogFileValidationEnabled:   aws.Bool(false),
						S3BucketName:               aws.String("another-bucket"),
						IncludeGlobalServiceEvents: aws.Bool(false),
					},
				},
			}, nil
		},
		GetTrailStatusFunc: func(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
			if *params.Name == "management-trail" {
				return &cloudtrail.GetTrailStatusOutput{
					IsLogging: aws.Bool(true),
				}, nil
			}
			return &cloudtrail.GetTrailStatusOutput{
				IsLogging: aws.Bool(false),
			}, nil
		},
	}

	collector := &CloudTrailCollector{client: mockCT}
	trails, err := collector.CollectTrails(context.Background())

	require.NoError(t, err)
	assert.Len(t, trails, 2)

	// Find management trail
	var mgmtTrail, regionalTrail *CloudTrailTrail
	for i := range trails {
		if trails[i].Name == "management-trail" {
			mgmtTrail = &trails[i]
		}
		if trails[i].Name == "regional-trail" {
			regionalTrail = &trails[i]
		}
	}

	require.NotNil(t, mgmtTrail)
	assert.True(t, mgmtTrail.IsMultiRegion)
	assert.True(t, mgmtTrail.IsLogging)
	assert.True(t, mgmtTrail.LogFileValidation)
	assert.True(t, mgmtTrail.IncludeGlobalEvents)
	assert.NotEmpty(t, mgmtTrail.KMSKeyID)

	require.NotNil(t, regionalTrail)
	assert.False(t, regionalTrail.IsMultiRegion)
	assert.False(t, regionalTrail.IsLogging)
	assert.False(t, regionalTrail.LogFileValidation)
}

func TestCloudTrailCollector_CollectTrails_NoTrails(t *testing.T) {
	mockCT := &MockCloudTrailClient{
		DescribeTrailsFunc: func(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
			return &cloudtrail.DescribeTrailsOutput{TrailList: []types.Trail{}}, nil
		},
	}

	collector := &CloudTrailCollector{client: mockCT}
	trails, err := collector.CollectTrails(context.Background())

	require.NoError(t, err)
	assert.Empty(t, trails)
}

func TestCloudTrailCollector_CollectTrails_APIError(t *testing.T) {
	mockCT := &MockCloudTrailClient{
		DescribeTrailsFunc: func(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := &CloudTrailCollector{client: mockCT}
	_, err := collector.CollectTrails(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// --- Negative tests ---

func TestCloudTrailCollector_CollectTrails_StatusError(t *testing.T) {
	// GetTrailStatus fails for a trail — should default to IsLogging=false
	mockCT := &MockCloudTrailClient{
		DescribeTrailsFunc: func(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
			return &cloudtrail.DescribeTrailsOutput{
				TrailList: []types.Trail{
					{
						Name:     aws.String("trail-ok"),
						TrailARN: aws.String("arn:aws:cloudtrail:us-east-1:123:trail/trail-ok"),
					},
					{
						Name:     aws.String("trail-err"),
						TrailARN: aws.String("arn:aws:cloudtrail:us-east-1:123:trail/trail-err"),
					},
				},
			}, nil
		},
		GetTrailStatusFunc: func(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
			if *params.Name == "trail-err" {
				return nil, errors.New("access denied")
			}
			return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true)}, nil
		},
	}

	collector := &CloudTrailCollector{client: mockCT}
	trails, err := collector.CollectTrails(context.Background())

	require.NoError(t, err, "should not fail when GetTrailStatus fails for one trail")
	require.Len(t, trails, 2)

	var trailOK, trailErr *CloudTrailTrail
	for i := range trails {
		switch trails[i].Name {
		case "trail-ok":
			trailOK = &trails[i]
		case "trail-err":
			trailErr = &trails[i]
		}
	}

	require.NotNil(t, trailOK)
	assert.True(t, trailOK.IsLogging)

	require.NotNil(t, trailErr)
	assert.False(t, trailErr.IsLogging, "should default to false when GetTrailStatus fails")
}

func TestCloudTrailCollector_ToEvidence(t *testing.T) {
	trail := CloudTrailTrail{
		Name:               "my-trail",
		ARN:                "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
		IsMultiRegion:      true,
		IsLogging:          true,
		LogFileValidation:  true,
		S3BucketName:       "my-bucket",
	}

	evidence := trail.ToEvidence("123456789012")

	assert.Equal(t, "aws", evidence.Collector)
	assert.Equal(t, "aws:cloudtrail:trail", evidence.ResourceType)
	assert.Equal(t, "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail", evidence.ResourceID)
	assert.NotEmpty(t, evidence.Hash)
}
