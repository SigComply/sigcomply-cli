package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	datasynctypes "github.com/aws/aws-sdk-go-v2/service/datasync/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockDataSyncClient struct {
	ListTasksFunc    func(ctx context.Context, params *datasync.ListTasksInput, optFns ...func(*datasync.Options)) (*datasync.ListTasksOutput, error)
	DescribeTaskFunc func(ctx context.Context, params *datasync.DescribeTaskInput, optFns ...func(*datasync.Options)) (*datasync.DescribeTaskOutput, error)
}

func (m *MockDataSyncClient) ListTasks(ctx context.Context, params *datasync.ListTasksInput, optFns ...func(*datasync.Options)) (*datasync.ListTasksOutput, error) {
	return m.ListTasksFunc(ctx, params, optFns...)
}

func (m *MockDataSyncClient) DescribeTask(ctx context.Context, params *datasync.DescribeTaskInput, optFns ...func(*datasync.Options)) (*datasync.DescribeTaskOutput, error) {
	if m.DescribeTaskFunc != nil {
		return m.DescribeTaskFunc(ctx, params, optFns...)
	}
	return &datasync.DescribeTaskOutput{}, nil
}

func TestDataSyncCollector_CollectTasks(t *testing.T) {
	mock := &MockDataSyncClient{
		ListTasksFunc: func(ctx context.Context, params *datasync.ListTasksInput, optFns ...func(*datasync.Options)) (*datasync.ListTasksOutput, error) {
			return &datasync.ListTasksOutput{
				Tasks: []datasynctypes.TaskListEntry{
					{
						Name:    awssdk.String("logged-task"),
						TaskArn: awssdk.String("arn:aws:datasync:us-east-1:123:task/task-abc"),
					},
					{
						Name:    awssdk.String("unlogged-task"),
						TaskArn: awssdk.String("arn:aws:datasync:us-east-1:123:task/task-def"),
					},
				},
			}, nil
		},
		DescribeTaskFunc: func(ctx context.Context, params *datasync.DescribeTaskInput, optFns ...func(*datasync.Options)) (*datasync.DescribeTaskOutput, error) {
			if awssdk.ToString(params.TaskArn) == "arn:aws:datasync:us-east-1:123:task/task-abc" {
				return &datasync.DescribeTaskOutput{
					CloudWatchLogGroupArn: awssdk.String("arn:aws:logs:us-east-1:123:log-group:/aws/datasync"),
				}, nil
			}
			return &datasync.DescribeTaskOutput{}, nil
		},
	}

	collector := NewDataSyncCollector(mock)
	tasks, err := collector.CollectTasks(context.Background())

	require.NoError(t, err)
	require.Len(t, tasks, 2)

	assert.Equal(t, "logged-task", tasks[0].Name)
	assert.True(t, tasks[0].LoggingEnabled)

	assert.Equal(t, "unlogged-task", tasks[1].Name)
	assert.False(t, tasks[1].LoggingEnabled)
}

func TestDataSyncCollector_CollectEvidence(t *testing.T) {
	mock := &MockDataSyncClient{
		ListTasksFunc: func(ctx context.Context, params *datasync.ListTasksInput, optFns ...func(*datasync.Options)) (*datasync.ListTasksOutput, error) {
			return &datasync.ListTasksOutput{
				Tasks: []datasynctypes.TaskListEntry{
					{Name: awssdk.String("task"), TaskArn: awssdk.String("arn:aws:datasync:us-east-1:123:task/task-abc")},
				},
			}, nil
		},
	}

	collector := NewDataSyncCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:datasync:task", ev[0].ResourceType)
}
