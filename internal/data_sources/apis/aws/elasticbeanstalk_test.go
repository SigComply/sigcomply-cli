package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebstypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockElasticBeanstalkClient struct {
	DescribeEnvironmentsFunc          func(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error)
	DescribeConfigurationSettingsFunc func(ctx context.Context, params *elasticbeanstalk.DescribeConfigurationSettingsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeConfigurationSettingsOutput, error)
}

func (m *MockElasticBeanstalkClient) DescribeEnvironments(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error) {
	return m.DescribeEnvironmentsFunc(ctx, params, optFns...)
}

func (m *MockElasticBeanstalkClient) DescribeConfigurationSettings(ctx context.Context, params *elasticbeanstalk.DescribeConfigurationSettingsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeConfigurationSettingsOutput, error) {
	if m.DescribeConfigurationSettingsFunc != nil {
		return m.DescribeConfigurationSettingsFunc(ctx, params, optFns...)
	}
	return &elasticbeanstalk.DescribeConfigurationSettingsOutput{}, nil
}

func TestBeanstalkCollector_CollectEnvironments(t *testing.T) {
	mock := &MockElasticBeanstalkClient{
		DescribeEnvironmentsFunc: func(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error) {
			return &elasticbeanstalk.DescribeEnvironmentsOutput{
				Environments: []ebstypes.EnvironmentDescription{
					{
						ApplicationName: awssdk.String("my-app"),
						EnvironmentName: awssdk.String("prod-env"),
						EnvironmentArn:  awssdk.String("arn:aws:elasticbeanstalk:us-east-1:123:environment/my-app/prod-env"),
					},
				},
			}, nil
		},
		DescribeConfigurationSettingsFunc: func(ctx context.Context, params *elasticbeanstalk.DescribeConfigurationSettingsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeConfigurationSettingsOutput, error) {
			return &elasticbeanstalk.DescribeConfigurationSettingsOutput{
				ConfigurationSettings: []ebstypes.ConfigurationSettingsDescription{
					{
						OptionSettings: []ebstypes.ConfigurationOptionSetting{
							{
								Namespace:  awssdk.String("aws:elasticbeanstalk:healthreporting:system"),
								OptionName: awssdk.String("SystemType"),
								Value:      awssdk.String("enhanced"),
							},
							{
								Namespace:  awssdk.String("aws:elasticbeanstalk:managedactions"),
								OptionName: awssdk.String("ManagedActionsEnabled"),
								Value:      awssdk.String("true"),
							},
							{
								Namespace:  awssdk.String("aws:elasticbeanstalk:cloudwatch:logs"),
								OptionName: awssdk.String("StreamLogs"),
								Value:      awssdk.String("true"),
							},
						},
					},
				},
			}, nil
		},
	}

	collector := NewBeanstalkCollector(mock)
	envs, err := collector.CollectEnvironments(context.Background())
	require.NoError(t, err)
	require.Len(t, envs, 1)

	env := envs[0]
	assert.Equal(t, "prod-env", env.EnvironmentName)
	assert.Equal(t, "arn:aws:elasticbeanstalk:us-east-1:123:environment/my-app/prod-env", env.ARN)
	assert.True(t, env.EnhancedHealthReporting)
	assert.True(t, env.ManagedUpdatesEnabled)
	assert.True(t, env.CloudWatchLogsEnabled)
}

func TestBeanstalkCollector_CollectEnvironments_NoConfigSettings(t *testing.T) {
	mock := &MockElasticBeanstalkClient{
		DescribeEnvironmentsFunc: func(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error) {
			return &elasticbeanstalk.DescribeEnvironmentsOutput{
				Environments: []ebstypes.EnvironmentDescription{
					{
						ApplicationName: awssdk.String("my-app"),
						EnvironmentName: awssdk.String("dev-env"),
						EnvironmentArn:  awssdk.String("arn:aws:elasticbeanstalk:us-east-1:123:environment/my-app/dev-env"),
					},
				},
			}, nil
		},
		DescribeConfigurationSettingsFunc: func(ctx context.Context, params *elasticbeanstalk.DescribeConfigurationSettingsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeConfigurationSettingsOutput, error) {
			return nil, errors.New("throttled")
		},
	}

	collector := NewBeanstalkCollector(mock)
	envs, err := collector.CollectEnvironments(context.Background())
	require.NoError(t, err)
	require.Len(t, envs, 1)

	// Defaults to false when config settings unavailable
	assert.False(t, envs[0].EnhancedHealthReporting)
	assert.False(t, envs[0].ManagedUpdatesEnabled)
	assert.False(t, envs[0].CloudWatchLogsEnabled)
}

func TestBeanstalkCollector_CollectEnvironments_Error(t *testing.T) {
	mock := &MockElasticBeanstalkClient{
		DescribeEnvironmentsFunc: func(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewBeanstalkCollector(mock)
	_, err := collector.CollectEnvironments(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to describe Elastic Beanstalk environments")
}

func TestBeanstalkCollector_CollectEvidence(t *testing.T) {
	mock := &MockElasticBeanstalkClient{
		DescribeEnvironmentsFunc: func(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error) {
			return &elasticbeanstalk.DescribeEnvironmentsOutput{
				Environments: []ebstypes.EnvironmentDescription{
					{
						ApplicationName: awssdk.String("my-app"),
						EnvironmentName: awssdk.String("prod-env"),
						EnvironmentArn:  awssdk.String("arn:aws:elasticbeanstalk:us-east-1:123:environment/my-app/prod-env"),
					},
				},
			}, nil
		},
	}

	collector := NewBeanstalkCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")
	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:elasticbeanstalk:environment", ev[0].ResourceType)
	assert.Equal(t, "123456789012", ev[0].Metadata.AccountID)
}
