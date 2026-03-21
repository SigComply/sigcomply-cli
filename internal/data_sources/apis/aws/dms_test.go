package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockDMSClient implements DMSClient for testing.
type MockDMSClient struct {
	DescribeReplicationInstancesFunc func(ctx context.Context, params *databasemigrationservice.DescribeReplicationInstancesInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationInstancesOutput, error)
	DescribeEndpointsFunc            func(ctx context.Context, params *databasemigrationservice.DescribeEndpointsInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeEndpointsOutput, error)
	DescribeReplicationTasksFunc     func(ctx context.Context, params *databasemigrationservice.DescribeReplicationTasksInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationTasksOutput, error)
}

func (m *MockDMSClient) DescribeReplicationInstances(ctx context.Context, params *databasemigrationservice.DescribeReplicationInstancesInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationInstancesOutput, error) {
	if m.DescribeReplicationInstancesFunc != nil {
		return m.DescribeReplicationInstancesFunc(ctx, params, optFns...)
	}
	return &databasemigrationservice.DescribeReplicationInstancesOutput{}, nil
}

func (m *MockDMSClient) DescribeEndpoints(ctx context.Context, params *databasemigrationservice.DescribeEndpointsInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeEndpointsOutput, error) {
	if m.DescribeEndpointsFunc != nil {
		return m.DescribeEndpointsFunc(ctx, params, optFns...)
	}
	return &databasemigrationservice.DescribeEndpointsOutput{}, nil
}

func (m *MockDMSClient) DescribeReplicationTasks(ctx context.Context, params *databasemigrationservice.DescribeReplicationTasksInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationTasksOutput, error) {
	if m.DescribeReplicationTasksFunc != nil {
		return m.DescribeReplicationTasksFunc(ctx, params, optFns...)
	}
	return &databasemigrationservice.DescribeReplicationTasksOutput{}, nil
}

func TestDMSCollector_CollectReplicationTasks(t *testing.T) {
	mock := &MockDMSClient{
		DescribeReplicationTasksFunc: func(ctx context.Context, params *databasemigrationservice.DescribeReplicationTasksInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationTasksOutput, error) {
			return &databasemigrationservice.DescribeReplicationTasksOutput{
				ReplicationTasks: []dmstypes.ReplicationTask{
					{
						ReplicationTaskIdentifier: awssdk.String("task-source-logging"),
						ReplicationTaskArn:        awssdk.String("arn:aws:dms:us-east-1:123456789012:task:source-logging"),
						ReplicationTaskSettings:   awssdk.String(`{"Logging":{"EnableLogging":true,"LogComponents":[{"Id":"SOURCE_CAPTURE","Severity":"LOGGER_SEVERITY_DEFAULT"}]}}`),
					},
					{
						ReplicationTaskIdentifier: awssdk.String("task-target-logging"),
						ReplicationTaskArn:        awssdk.String("arn:aws:dms:us-east-1:123456789012:task:target-logging"),
						ReplicationTaskSettings:   awssdk.String(`{"Logging":{"EnableLogging":true,"LogComponents":[{"Id":"TARGET_LOAD","Severity":"LOGGER_SEVERITY_DEFAULT"}]}}`),
					},
					{
						ReplicationTaskIdentifier: awssdk.String("task-no-logging"),
						ReplicationTaskArn:        awssdk.String("arn:aws:dms:us-east-1:123456789012:task:no-logging"),
						ReplicationTaskSettings:   awssdk.String(`{"Logging":{"EnableLogging":false,"LogComponents":[]}}`),
					},
				},
			}, nil
		},
	}

	collector := NewDMSCollector(mock)
	tasks, err := collector.CollectReplicationTasks(context.Background())

	require.NoError(t, err)
	require.Len(t, tasks, 3)

	assert.Equal(t, "task-source-logging", tasks[0].TaskID)
	assert.Equal(t, "arn:aws:dms:us-east-1:123456789012:task:source-logging", tasks[0].ARN)
	assert.True(t, tasks[0].SourceLoggingEnabled, "SOURCE_CAPTURE in settings should set SourceLoggingEnabled")
	assert.False(t, tasks[0].TargetLoggingEnabled)

	assert.Equal(t, "task-target-logging", tasks[1].TaskID)
	assert.False(t, tasks[1].SourceLoggingEnabled)
	assert.True(t, tasks[1].TargetLoggingEnabled, "TARGET_LOAD in settings should set TargetLoggingEnabled")

	assert.Equal(t, "task-no-logging", tasks[2].TaskID)
	assert.False(t, tasks[2].SourceLoggingEnabled)
	assert.False(t, tasks[2].TargetLoggingEnabled)
}

func TestDMSCollector_CollectReplicationTasks_NilSettings(t *testing.T) {
	mock := &MockDMSClient{
		DescribeReplicationTasksFunc: func(ctx context.Context, params *databasemigrationservice.DescribeReplicationTasksInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationTasksOutput, error) {
			return &databasemigrationservice.DescribeReplicationTasksOutput{
				ReplicationTasks: []dmstypes.ReplicationTask{
					{
						ReplicationTaskIdentifier: awssdk.String("task-nil-settings"),
						ReplicationTaskArn:        awssdk.String("arn:aws:dms:us-east-1:123456789012:task:nil-settings"),
						ReplicationTaskSettings:   nil,
					},
				},
			}, nil
		},
	}

	collector := NewDMSCollector(mock)
	tasks, err := collector.CollectReplicationTasks(context.Background())

	require.NoError(t, err)
	require.Len(t, tasks, 1)
	assert.Equal(t, "task-nil-settings", tasks[0].TaskID)
	assert.False(t, tasks[0].SourceLoggingEnabled, "nil settings should default to false")
	assert.False(t, tasks[0].TargetLoggingEnabled, "nil settings should default to false")
}

func TestDMSCollector_CollectReplicationTasks_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockDMSClient{
		DescribeReplicationTasksFunc: func(ctx context.Context, params *databasemigrationservice.DescribeReplicationTasksInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationTasksOutput, error) {
			callCount++
			if callCount == 1 {
				return &databasemigrationservice.DescribeReplicationTasksOutput{
					ReplicationTasks: []dmstypes.ReplicationTask{
						{
							ReplicationTaskIdentifier: awssdk.String("task-1"),
							ReplicationTaskArn:        awssdk.String("arn:aws:dms:us-east-1:123456789012:task:task-1"),
						},
					},
					Marker: awssdk.String("page2"),
				}, nil
			}
			return &databasemigrationservice.DescribeReplicationTasksOutput{
				ReplicationTasks: []dmstypes.ReplicationTask{
					{
						ReplicationTaskIdentifier: awssdk.String("task-2"),
						ReplicationTaskArn:        awssdk.String("arn:aws:dms:us-east-1:123456789012:task:task-2"),
					},
				},
			}, nil
		},
	}

	collector := NewDMSCollector(mock)
	tasks, err := collector.CollectReplicationTasks(context.Background())

	require.NoError(t, err)
	assert.Len(t, tasks, 2)
	assert.Equal(t, 2, callCount, "should have paginated with 2 API calls")
}

func TestDMSCollector_CollectReplicationTasks_Error(t *testing.T) {
	mock := &MockDMSClient{
		DescribeReplicationTasksFunc: func(ctx context.Context, params *databasemigrationservice.DescribeReplicationTasksInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationTasksOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewDMSCollector(mock)
	_, err := collector.CollectReplicationTasks(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to describe DMS replication tasks")
}

func TestDMSReplicationTask_ToEvidence(t *testing.T) {
	task := &DMSReplicationTask{
		TaskID:               "my-task",
		ARN:                  "arn:aws:dms:us-east-1:123456789012:task:my-task",
		SourceLoggingEnabled: true,
		TargetLoggingEnabled: false,
	}

	ev := task.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:dms:replication-task", ev.ResourceType)
	assert.Equal(t, "arn:aws:dms:us-east-1:123456789012:task:my-task", ev.ResourceID)
	assert.Equal(t, "123456789012", ev.Metadata.AccountID)
	assert.NotEmpty(t, ev.Hash)
}

func TestDMSCollector_CollectEvidence_IncludesTasks(t *testing.T) {
	mock := &MockDMSClient{
		DescribeReplicationInstancesFunc: func(ctx context.Context, params *databasemigrationservice.DescribeReplicationInstancesInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationInstancesOutput, error) {
			return &databasemigrationservice.DescribeReplicationInstancesOutput{}, nil
		},
		DescribeReplicationTasksFunc: func(ctx context.Context, params *databasemigrationservice.DescribeReplicationTasksInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationTasksOutput, error) {
			return &databasemigrationservice.DescribeReplicationTasksOutput{
				ReplicationTasks: []dmstypes.ReplicationTask{
					{
						ReplicationTaskIdentifier: awssdk.String("my-task"),
						ReplicationTaskArn:        awssdk.String("arn:aws:dms:us-east-1:123456789012:task:my-task"),
					},
				},
			}, nil
		},
	}

	collector := NewDMSCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	var taskEvidence []string
	for _, e := range ev {
		if e.ResourceType == "aws:dms:replication-task" {
			taskEvidence = append(taskEvidence, e.ResourceID)
		}
	}
	assert.Len(t, taskEvidence, 1, "should include replication task evidence")
	assert.Equal(t, "arn:aws:dms:us-east-1:123456789012:task:my-task", taskEvidence[0])
}
