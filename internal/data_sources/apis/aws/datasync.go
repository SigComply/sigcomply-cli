package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// DataSyncClient defines the interface for DataSync operations.
type DataSyncClient interface {
	ListTasks(ctx context.Context, params *datasync.ListTasksInput, optFns ...func(*datasync.Options)) (*datasync.ListTasksOutput, error)
	DescribeTask(ctx context.Context, params *datasync.DescribeTaskInput, optFns ...func(*datasync.Options)) (*datasync.DescribeTaskOutput, error)
}

// DataSyncTask represents a DataSync task.
type DataSyncTask struct {
	Name           string `json:"name"`
	ARN            string `json:"arn"`
	LoggingEnabled bool   `json:"logging_enabled"`
}

// ToEvidence converts a DataSyncTask to Evidence.
func (t *DataSyncTask) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(t) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:datasync:task", t.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// DataSyncCollector collects DataSync task data.
type DataSyncCollector struct {
	client DataSyncClient
}

// NewDataSyncCollector creates a new DataSync collector.
func NewDataSyncCollector(client DataSyncClient) *DataSyncCollector {
	return &DataSyncCollector{client: client}
}

// CollectTasks retrieves all DataSync tasks with logging status.
func (c *DataSyncCollector) CollectTasks(ctx context.Context) ([]DataSyncTask, error) {
	var tasks []DataSyncTask
	var nextToken *string

	for {
		output, err := c.client.ListTasks(ctx, &datasync.ListTasksInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list DataSync tasks: %w", err)
		}

		for _, item := range output.Tasks {
			task := DataSyncTask{
				Name: awssdk.ToString(item.Name),
				ARN:  awssdk.ToString(item.TaskArn),
			}

			c.enrichTask(ctx, &task)
			tasks = append(tasks, task)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return tasks, nil
}

// enrichTask retrieves detailed task information and sets logging status.
func (c *DataSyncCollector) enrichTask(ctx context.Context, task *DataSyncTask) {
	output, err := c.client.DescribeTask(ctx, &datasync.DescribeTaskInput{
		TaskArn: awssdk.String(task.ARN),
	})
	if err != nil {
		return // Fail-safe
	}

	// CloudWatchLogGroupArn being non-empty means logging is enabled
	task.LoggingEnabled = awssdk.ToString(output.CloudWatchLogGroupArn) != ""
	if task.Name == "" {
		task.Name = awssdk.ToString(output.Name)
	}
}

// CollectEvidence collects DataSync tasks as evidence.
func (c *DataSyncCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	tasks, err := c.CollectTasks(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(tasks))
	for i := range tasks {
		evidenceList = append(evidenceList, tasks[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
