package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockSNSClient struct {
	ListTopicsFunc         func(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	GetTopicAttributesFunc func(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
}

func (m *MockSNSClient) ListTopics(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	return m.ListTopicsFunc(ctx, params, optFns...)
}

func (m *MockSNSClient) GetTopicAttributes(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	if m.GetTopicAttributesFunc != nil {
		return m.GetTopicAttributesFunc(ctx, params, optFns...)
	}
	return &sns.GetTopicAttributesOutput{Attributes: map[string]string{}}, nil
}

func TestSNSCollector_CollectTopics(t *testing.T) {
	mock := &MockSNSClient{
		ListTopicsFunc: func(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
			return &sns.ListTopicsOutput{
				Topics: []snstypes.Topic{
					{TopicArn: aws.String("arn:aws:sns:us-east-1:123:encrypted-topic")},
					{TopicArn: aws.String("arn:aws:sns:us-east-1:123:unencrypted-topic")},
				},
			}, nil
		},
		GetTopicAttributesFunc: func(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
			if *params.TopicArn == "arn:aws:sns:us-east-1:123:encrypted-topic" {
				return &sns.GetTopicAttributesOutput{
					Attributes: map[string]string{
						"KmsMasterKeyId": "arn:aws:kms:us-east-1:123:key/abc-123",
					},
				}, nil
			}
			return &sns.GetTopicAttributesOutput{Attributes: map[string]string{}}, nil
		},
	}

	collector := NewSNSCollector(mock)
	topics, err := collector.CollectTopics(context.Background())

	require.NoError(t, err)
	require.Len(t, topics, 2)

	// Encrypted topic
	assert.Equal(t, "encrypted-topic", topics[0].Name)
	assert.True(t, topics[0].Encrypted)
	assert.Equal(t, "arn:aws:kms:us-east-1:123:key/abc-123", topics[0].KMSKeyID)

	// Unencrypted topic
	assert.Equal(t, "unencrypted-topic", topics[1].Name)
	assert.False(t, topics[1].Encrypted)
	assert.Empty(t, topics[1].KMSKeyID)
}

func TestSNSCollector_CollectTopics_Error(t *testing.T) {
	mock := &MockSNSClient{
		ListTopicsFunc: func(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewSNSCollector(mock)
	_, err := collector.CollectTopics(context.Background())
	assert.Error(t, err)
}

func TestSNSCollector_EnrichAttributes_Error_FailSafe(t *testing.T) {
	mock := &MockSNSClient{
		ListTopicsFunc: func(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
			return &sns.ListTopicsOutput{
				Topics: []snstypes.Topic{
					{TopicArn: aws.String("arn:aws:sns:us-east-1:123:my-topic")},
				},
			}, nil
		},
		GetTopicAttributesFunc: func(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewSNSCollector(mock)
	topics, err := collector.CollectTopics(context.Background())

	require.NoError(t, err)
	require.Len(t, topics, 1)
	assert.False(t, topics[0].Encrypted, "should default to not encrypted on error")
}

func TestSNSTopic_ToEvidence(t *testing.T) {
	topic := SNSTopic{
		TopicARN:  "arn:aws:sns:us-east-1:123:my-topic",
		Name:      "my-topic",
		Encrypted: true,
		KMSKeyID:  "key-123",
	}

	ev := topic.ToEvidence("123")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:sns:topic", ev.ResourceType)
	assert.Equal(t, "arn:aws:sns:us-east-1:123:my-topic", ev.ResourceID)
	assert.NotEmpty(t, ev.Hash)
}
