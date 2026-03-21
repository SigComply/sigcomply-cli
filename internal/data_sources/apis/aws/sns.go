package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// SNSClient defines the interface for SNS operations we use.
type SNSClient interface {
	ListTopics(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	GetTopicAttributes(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
}

// SNSTopic represents an SNS topic with its encryption configuration.
type SNSTopic struct {
	TopicARN               string `json:"topic_arn"`
	Name                   string `json:"name"`
	KMSKeyID               string `json:"kms_key_id,omitempty"`
	Encrypted              bool   `json:"encrypted"`
	DeliveryLoggingEnabled bool   `json:"delivery_logging_enabled"`
}

// ToEvidence converts an SNSTopic to Evidence.
func (t *SNSTopic) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(t) //nolint:errcheck
	ev := evidence.New("aws", "aws:sns:topic", t.TopicARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// SNSCollector collects SNS topic data.
type SNSCollector struct {
	client SNSClient
}

// NewSNSCollector creates a new SNS collector.
func NewSNSCollector(client SNSClient) *SNSCollector {
	return &SNSCollector{client: client}
}

// CollectTopics retrieves all SNS topics with their encryption status.
func (c *SNSCollector) CollectTopics(ctx context.Context) ([]SNSTopic, error) {
	var topics []SNSTopic
	var nextToken *string

	for {
		output, err := c.client.ListTopics(ctx, &sns.ListTopicsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list SNS topics: %w", err)
		}

		for _, t := range output.Topics {
			arn := awssdk.ToString(t.TopicArn)
			topic := SNSTopic{
				TopicARN: arn,
				Name:     extractTopicName(arn),
			}

			c.enrichAttributes(ctx, &topic)
			topics = append(topics, topic)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return topics, nil
}

// enrichAttributes fetches topic attributes for encryption info.
func (c *SNSCollector) enrichAttributes(ctx context.Context, topic *SNSTopic) {
	output, err := c.client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
		TopicArn: awssdk.String(topic.TopicARN),
	})
	if err != nil {
		return // Fail-safe
	}

	if kmsKeyID, ok := output.Attributes["KmsMasterKeyId"]; ok && kmsKeyID != "" {
		topic.KMSKeyID = kmsKeyID
		topic.Encrypted = true
	}

	// Check for delivery status logging (any protocol)
	deliveryLogAttrs := []string{
		"HTTPSuccessFeedbackRoleArn",
		"HTTPSSuccessFeedbackRoleArn",
		"LambdaSuccessFeedbackRoleArn",
		"SQSSuccessFeedbackRoleArn",
		"ApplicationSuccessFeedbackRoleArn",
		"FirehoseSuccessFeedbackRoleArn",
	}
	for _, attr := range deliveryLogAttrs {
		if val, ok := output.Attributes[attr]; ok && val != "" {
			topic.DeliveryLoggingEnabled = true
			break
		}
	}
}

// extractTopicName extracts the topic name from an ARN.
func extractTopicName(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}

// CollectEvidence collects SNS topics as evidence.
func (c *SNSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	topics, err := c.CollectTopics(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(topics))
	for i := range topics {
		evidenceList = append(evidenceList, topics[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
