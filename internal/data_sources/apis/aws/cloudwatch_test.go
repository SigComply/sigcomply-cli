package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockCloudWatchLogsClient implements CloudWatchLogsClient for testing.
type MockCloudWatchLogsClient struct {
	DescribeLogGroupsFunc func(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
}

func (m *MockCloudWatchLogsClient) DescribeLogGroups(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	return m.DescribeLogGroupsFunc(ctx, params, optFns...)
}

func TestCloudWatchCollector_CollectLogGroups(t *testing.T) {
	tests := []struct {
		name       string
		mockGroups []cwltypes.LogGroup
		mockErr    error
		wantCount  int
		wantError  bool
	}{
		{
			name: "log group with retention",
			mockGroups: []cwltypes.LogGroup{
				{
					LogGroupName:    awssdk.String("/aws/lambda/my-func"),
					Arn:             awssdk.String("arn:aws:logs:us-east-1:123:log-group:/aws/lambda/my-func"),
					RetentionInDays: awssdk.Int32(90),
					StoredBytes:     awssdk.Int64(1024),
					KmsKeyId:        awssdk.String("arn:aws:kms:us-east-1:123:key/abc"),
				},
			},
			wantCount: 1,
		},
		{
			name: "log group without retention (never expires)",
			mockGroups: []cwltypes.LogGroup{
				{
					LogGroupName: awssdk.String("/aws/cloudtrail"),
					Arn:          awssdk.String("arn:aws:logs:us-east-1:123:log-group:/aws/cloudtrail"),
					StoredBytes:  awssdk.Int64(5000),
				},
			},
			wantCount: 1,
		},
		{
			name:       "no log groups",
			mockGroups: []cwltypes.LogGroup{},
			wantCount:  0,
		},
		{
			name:      "API error",
			mockErr:   errors.New("access denied"),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockCloudWatchLogsClient{
				DescribeLogGroupsFunc: func(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return &cloudwatchlogs.DescribeLogGroupsOutput{LogGroups: tt.mockGroups}, nil
				},
			}

			collector := NewCloudWatchCollector(mock)
			groups, err := collector.CollectLogGroups(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, groups, tt.wantCount)

			if tt.name == "log group with retention" {
				assert.Equal(t, 90, groups[0].RetentionDays)
				assert.True(t, groups[0].HasRetention)
				assert.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", groups[0].KMSKeyID)
			}

			if tt.name == "log group without retention (never expires)" {
				assert.Equal(t, 0, groups[0].RetentionDays)
				assert.False(t, groups[0].HasRetention)
			}
		})
	}
}

func TestCloudWatchCollector_CollectLogGroups_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockCloudWatchLogsClient{
		DescribeLogGroupsFunc: func(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
			callCount++
			if callCount == 1 {
				return &cloudwatchlogs.DescribeLogGroupsOutput{
					LogGroups: []cwltypes.LogGroup{
						{LogGroupName: awssdk.String("group-1"), Arn: awssdk.String("arn:1")},
					},
					NextToken: awssdk.String("token1"),
				}, nil
			}
			return &cloudwatchlogs.DescribeLogGroupsOutput{
				LogGroups: []cwltypes.LogGroup{
					{LogGroupName: awssdk.String("group-2"), Arn: awssdk.String("arn:2")},
				},
			}, nil
		},
	}

	collector := NewCloudWatchCollector(mock)
	groups, err := collector.CollectLogGroups(context.Background())

	require.NoError(t, err)
	assert.Len(t, groups, 2)
	assert.Equal(t, 2, callCount)
}

func TestLogGroup_ToEvidence(t *testing.T) {
	lg := &LogGroup{
		Name:          "/aws/lambda/test",
		ARN:           "arn:aws:logs:us-east-1:123:log-group:/aws/lambda/test",
		RetentionDays: 90,
		HasRetention:  true,
	}

	ev := lg.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:logs:log-group", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}

// --- Negative Tests ---

func TestCloudWatchCollector_CollectLogGroups_PaginationErrorMidStream(t *testing.T) {
	callCount := 0
	mock := &MockCloudWatchLogsClient{
		DescribeLogGroupsFunc: func(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
			callCount++
			if callCount == 1 {
				return &cloudwatchlogs.DescribeLogGroupsOutput{
					LogGroups: []cwltypes.LogGroup{
						{LogGroupName: awssdk.String("group-1"), Arn: awssdk.String("arn:1")},
					},
					NextToken: awssdk.String("token1"),
				}, nil
			}
			return nil, errors.New("service error on page 2")
		},
	}

	collector := NewCloudWatchCollector(mock)
	_, err := collector.CollectLogGroups(context.Background())

	assert.Error(t, err, "pagination error should propagate")
	assert.Contains(t, err.Error(), "failed to describe log groups")
}

func TestCloudWatchCollector_CollectLogGroups_NilOptionalFields(t *testing.T) {
	mock := &MockCloudWatchLogsClient{
		DescribeLogGroupsFunc: func(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
			return &cloudwatchlogs.DescribeLogGroupsOutput{
				LogGroups: []cwltypes.LogGroup{
					{
						LogGroupName:    awssdk.String("minimal"),
						Arn:             awssdk.String("arn:minimal"),
						RetentionInDays: nil,
						KmsKeyId:        nil,
						StoredBytes:     nil,
					},
				},
			}, nil
		},
	}

	collector := NewCloudWatchCollector(mock)
	groups, err := collector.CollectLogGroups(context.Background())

	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, 0, groups[0].RetentionDays, "nil retention should be 0")
	assert.False(t, groups[0].HasRetention, "nil retention means no retention set")
	assert.Empty(t, groups[0].KMSKeyID, "nil KMS key should be empty")
	assert.Equal(t, int64(0), groups[0].StoredBytes, "nil stored bytes should be 0")
}

func TestCloudWatchCollector_CollectEvidence_Error(t *testing.T) {
	mock := &MockCloudWatchLogsClient{
		DescribeLogGroupsFunc: func(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewCloudWatchCollector(mock)
	_, err := collector.CollectEvidence(context.Background(), "123456789012")

	assert.Error(t, err, "CollectEvidence should propagate error")
}
