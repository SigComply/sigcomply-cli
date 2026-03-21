package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// SQSClient defines the interface for SQS operations we use.
type SQSClient interface {
	ListQueues(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributes(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

// SQSQueue represents an SQS queue with its encryption configuration.
type SQSQueue struct {
	QueueURL              string `json:"queue_url"`
	QueueARN              string `json:"queue_arn"`
	Name                  string `json:"name"`
	KMSKeyID              string `json:"kms_key_id,omitempty"`
	SSEEnabled            bool   `json:"sse_enabled"`
	SQSManagedEncryption  bool   `json:"sqs_managed_encryption"`
	HasDLQ                bool   `json:"has_dlq"`
}

// ToEvidence converts an SQSQueue to Evidence.
func (q *SQSQueue) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(q) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := q.QueueARN
	if resourceID == "" {
		resourceID = q.QueueURL
	}
	ev := evidence.New("aws", "aws:sqs:queue", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// SQSCollector collects SQS queue data.
type SQSCollector struct {
	client SQSClient
}

// NewSQSCollector creates a new SQS collector.
func NewSQSCollector(client SQSClient) *SQSCollector {
	return &SQSCollector{client: client}
}

// CollectQueues retrieves all SQS queues with their encryption status.
func (c *SQSCollector) CollectQueues(ctx context.Context) ([]SQSQueue, error) {
	var queues []SQSQueue
	var nextToken *string

	for {
		output, err := c.client.ListQueues(ctx, &sqs.ListQueuesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list SQS queues: %w", err)
		}

		for _, url := range output.QueueUrls {
			queue := SQSQueue{
				QueueURL: url,
				Name:     extractQueueName(url),
			}

			c.enrichAttributes(ctx, &queue)
			queues = append(queues, queue)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return queues, nil
}

// enrichAttributes fetches queue attributes for encryption info.
func (c *SQSCollector) enrichAttributes(ctx context.Context, queue *SQSQueue) {
	output, err := c.client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl: awssdk.String(queue.QueueURL),
		AttributeNames: []sqstypes.QueueAttributeName{
			sqstypes.QueueAttributeNameQueueArn,
			sqstypes.QueueAttributeNameKmsMasterKeyId,
			sqstypes.QueueAttributeNameSqsManagedSseEnabled,
			sqstypes.QueueAttributeNameRedrivePolicy,
		},
	})
	if err != nil {
		return // Fail-safe
	}

	if arn, ok := output.Attributes["QueueArn"]; ok {
		queue.QueueARN = arn
	}

	if kmsKeyID, ok := output.Attributes["KmsMasterKeyId"]; ok && kmsKeyID != "" {
		queue.KMSKeyID = kmsKeyID
		queue.SSEEnabled = true
	}

	if sqsManaged, ok := output.Attributes["SqsManagedSseEnabled"]; ok && sqsManaged == statusTrue {
		queue.SQSManagedEncryption = true
	}

	if redrivePolicy, ok := output.Attributes["RedrivePolicy"]; ok && redrivePolicy != "" {
		queue.HasDLQ = true
	}
}

// extractQueueName extracts the queue name from a URL.
func extractQueueName(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

// CollectEvidence collects SQS queues as evidence.
func (c *SQSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	queues, err := c.CollectQueues(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(queues))
	for i := range queues {
		evidenceList = append(evidenceList, queues[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
