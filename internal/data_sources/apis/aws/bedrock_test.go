package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockBedrockClient struct {
	GetModelInvocationLoggingConfigurationFunc func(ctx context.Context, params *bedrock.GetModelInvocationLoggingConfigurationInput, optFns ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error)
}

func (m *MockBedrockClient) GetModelInvocationLoggingConfiguration(ctx context.Context, params *bedrock.GetModelInvocationLoggingConfigurationInput, optFns ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error) {
	return m.GetModelInvocationLoggingConfigurationFunc(ctx, params, optFns...)
}

func TestBedrockCollector_LoggingEnabled(t *testing.T) {
	mock := &MockBedrockClient{
		GetModelInvocationLoggingConfigurationFunc: func(ctx context.Context, params *bedrock.GetModelInvocationLoggingConfigurationInput, optFns ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error) {
			return &bedrock.GetModelInvocationLoggingConfigurationOutput{
				LoggingConfig: &bedrocktypes.LoggingConfig{
					CloudWatchConfig: &bedrocktypes.CloudWatchConfig{
						LogGroupName: awssdk.String("/aws/bedrock/invocations"),
					},
				},
			}, nil
		},
	}

	collector := NewBedrockCollector(mock, "us-east-1")
	config, err := collector.CollectLoggingConfig(context.Background())

	require.NoError(t, err)
	assert.True(t, config.InvocationLoggingEnabled)
}

func TestBedrockCollector_LoggingDisabled(t *testing.T) {
	mock := &MockBedrockClient{
		GetModelInvocationLoggingConfigurationFunc: func(ctx context.Context, params *bedrock.GetModelInvocationLoggingConfigurationInput, optFns ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error) {
			return &bedrock.GetModelInvocationLoggingConfigurationOutput{}, nil
		},
	}

	collector := NewBedrockCollector(mock, "us-east-1")
	config, err := collector.CollectLoggingConfig(context.Background())

	require.NoError(t, err)
	assert.False(t, config.InvocationLoggingEnabled)
}

func TestBedrockCollector_CollectEvidence(t *testing.T) {
	mock := &MockBedrockClient{
		GetModelInvocationLoggingConfigurationFunc: func(ctx context.Context, params *bedrock.GetModelInvocationLoggingConfigurationInput, optFns ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error) {
			return &bedrock.GetModelInvocationLoggingConfigurationOutput{}, nil
		},
	}

	collector := NewBedrockCollector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:bedrock:model", ev[0].ResourceType)
}
