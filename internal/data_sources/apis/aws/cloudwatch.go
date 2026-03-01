package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// CloudWatchLogsClient defines the interface for CloudWatch Logs operations.
type CloudWatchLogsClient interface {
	DescribeLogGroups(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
}

// LogGroup represents a CloudWatch log group.
type LogGroup struct {
	Name          string `json:"name"`
	ARN           string `json:"arn"`
	RetentionDays int    `json:"retention_days"`
	HasRetention  bool   `json:"has_retention"`
	KMSKeyID      string `json:"kms_key_id,omitempty"`
	StoredBytes   int64  `json:"stored_bytes"`
}

// ToEvidence converts a LogGroup to Evidence.
func (lg *LogGroup) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(lg) //nolint:errcheck
	ev := evidence.New("aws", "aws:logs:log-group", lg.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// CloudWatchCollector collects CloudWatch Logs data.
type CloudWatchCollector struct {
	client CloudWatchLogsClient
}

// NewCloudWatchCollector creates a new CloudWatch Logs collector.
func NewCloudWatchCollector(client CloudWatchLogsClient) *CloudWatchCollector {
	return &CloudWatchCollector{client: client}
}

// CollectLogGroups retrieves all CloudWatch log groups.
func (c *CloudWatchCollector) CollectLogGroups(ctx context.Context) ([]LogGroup, error) {
	var groups []LogGroup
	var nextToken *string

	for {
		output, err := c.client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe log groups: %w", err)
		}

		for _, lg := range output.LogGroups {
			group := LogGroup{
				Name:        awssdk.ToString(lg.LogGroupName),
				ARN:         awssdk.ToString(lg.Arn),
				StoredBytes: awssdk.ToInt64(lg.StoredBytes),
			}

			if lg.RetentionInDays != nil {
				group.RetentionDays = int(awssdk.ToInt32(lg.RetentionInDays))
				group.HasRetention = true
			}

			if lg.KmsKeyId != nil {
				group.KMSKeyID = awssdk.ToString(lg.KmsKeyId)
			}

			groups = append(groups, group)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return groups, nil
}

// CollectEvidence collects CloudWatch log groups as evidence.
func (c *CloudWatchCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	groups, err := c.CollectLogGroups(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(groups))
	for i := range groups {
		evidenceList = append(evidenceList, groups[i].ToEvidence(accountID))
	}

	return evidenceList, nil
}
