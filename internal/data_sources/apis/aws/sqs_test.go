package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockSQSClient struct {
	ListQueuesFunc        func(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributesFunc func(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

func (m *MockSQSClient) ListQueues(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	return m.ListQueuesFunc(ctx, params, optFns...)
}

func (m *MockSQSClient) GetQueueAttributes(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	if m.GetQueueAttributesFunc != nil {
		return m.GetQueueAttributesFunc(ctx, params, optFns...)
	}
	return &sqs.GetQueueAttributesOutput{Attributes: map[string]string{}}, nil
}

func TestSQSCollector_CollectQueues(t *testing.T) {
	mock := &MockSQSClient{
		ListQueuesFunc: func(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
			return &sqs.ListQueuesOutput{
				QueueUrls: []string{
					"https://sqs.us-east-1.amazonaws.com/123/kms-queue",
					"https://sqs.us-east-1.amazonaws.com/123/sqs-managed-queue",
					"https://sqs.us-east-1.amazonaws.com/123/unencrypted-queue",
				},
			}, nil
		},
		GetQueueAttributesFunc: func(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
			switch *params.QueueUrl {
			case "https://sqs.us-east-1.amazonaws.com/123/kms-queue":
				return &sqs.GetQueueAttributesOutput{
					Attributes: map[string]string{
						"QueueArn":       "arn:aws:sqs:us-east-1:123:kms-queue",
						"KmsMasterKeyId": "arn:aws:kms:us-east-1:123:key/abc",
					},
				}, nil
			case "https://sqs.us-east-1.amazonaws.com/123/sqs-managed-queue":
				return &sqs.GetQueueAttributesOutput{
					Attributes: map[string]string{
						"QueueArn":             "arn:aws:sqs:us-east-1:123:sqs-managed-queue",
						"SqsManagedSseEnabled": "true",
					},
				}, nil
			default:
				return &sqs.GetQueueAttributesOutput{
					Attributes: map[string]string{
						"QueueArn": "arn:aws:sqs:us-east-1:123:unencrypted-queue",
					},
				}, nil
			}
		},
	}

	collector := NewSQSCollector(mock)
	queues, err := collector.CollectQueues(context.Background())

	require.NoError(t, err)
	require.Len(t, queues, 3)

	// KMS encrypted
	assert.Equal(t, "kms-queue", queues[0].Name)
	assert.True(t, queues[0].SSEEnabled)
	assert.False(t, queues[0].SQSManagedEncryption)
	assert.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", queues[0].KMSKeyID)

	// SQS-managed encryption
	assert.Equal(t, "sqs-managed-queue", queues[1].Name)
	assert.False(t, queues[1].SSEEnabled)
	assert.True(t, queues[1].SQSManagedEncryption)

	// Unencrypted
	assert.Equal(t, "unencrypted-queue", queues[2].Name)
	assert.False(t, queues[2].SSEEnabled)
	assert.False(t, queues[2].SQSManagedEncryption)
}

func TestSQSCollector_CollectQueues_Error(t *testing.T) {
	mock := &MockSQSClient{
		ListQueuesFunc: func(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewSQSCollector(mock)
	_, err := collector.CollectQueues(context.Background())
	assert.Error(t, err)
}

func TestSQSCollector_EnrichAttributes_Error_FailSafe(t *testing.T) {
	mock := &MockSQSClient{
		ListQueuesFunc: func(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
			return &sqs.ListQueuesOutput{
				QueueUrls: []string{"https://sqs.us-east-1.amazonaws.com/123/my-queue"},
			}, nil
		},
		GetQueueAttributesFunc: func(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewSQSCollector(mock)
	queues, err := collector.CollectQueues(context.Background())

	require.NoError(t, err)
	require.Len(t, queues, 1)
	assert.False(t, queues[0].SSEEnabled)
	assert.False(t, queues[0].SQSManagedEncryption)
}

func TestSQSQueue_ToEvidence(t *testing.T) {
	queue := SQSQueue{
		QueueURL:  "https://sqs.us-east-1.amazonaws.com/123/my-queue",
		QueueARN:  "arn:aws:sqs:us-east-1:123:my-queue",
		Name:      "my-queue",
		SSEEnabled: true,
		KMSKeyID:  "key-123",
	}

	ev := queue.ToEvidence("123")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:sqs:queue", ev.ResourceType)
	assert.Equal(t, "arn:aws:sqs:us-east-1:123:my-queue", ev.ResourceID)
	assert.NotEmpty(t, ev.Hash)
}

// Ensure sqstypes is referenced (used in production code for QueueAttributeName constants).
var _ = sqstypes.QueueAttributeNameQueueArn
