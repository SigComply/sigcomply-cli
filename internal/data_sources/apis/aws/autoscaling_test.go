package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	autoscalingtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockAutoScalingClient struct {
	DescribeAutoScalingGroupsFunc    func(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
	DescribeLaunchConfigurationsFunc func(ctx context.Context, params *autoscaling.DescribeLaunchConfigurationsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error)
}

func (m *MockAutoScalingClient) DescribeAutoScalingGroups(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	return m.DescribeAutoScalingGroupsFunc(ctx, params, optFns...)
}

func (m *MockAutoScalingClient) DescribeLaunchConfigurations(ctx context.Context, params *autoscaling.DescribeLaunchConfigurationsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error) {
	if m.DescribeLaunchConfigurationsFunc != nil {
		return m.DescribeLaunchConfigurationsFunc(ctx, params, optFns...)
	}
	return &autoscaling.DescribeLaunchConfigurationsOutput{}, nil
}

func TestAutoScalingCollector_CollectGroups(t *testing.T) {
	mock := &MockAutoScalingClient{
		DescribeAutoScalingGroupsFunc: func(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
			return &autoscaling.DescribeAutoScalingGroupsOutput{
				AutoScalingGroups: []autoscalingtypes.AutoScalingGroup{
					{
						AutoScalingGroupName: awssdk.String("prod-asg"),
						AutoScalingGroupARN:  awssdk.String("arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/prod-asg"),
						HealthCheckType:      awssdk.String("ELB"),
						AvailabilityZones:    []string{"us-east-1a", "us-east-1b"},
						LaunchTemplate: &autoscalingtypes.LaunchTemplateSpecification{
							LaunchTemplateId: awssdk.String("lt-abc123"),
						},
					},
					{
						AutoScalingGroupName:    awssdk.String("dev-asg"),
						AutoScalingGroupARN:     awssdk.String("arn:aws:autoscaling:us-east-1:123:autoScalingGroup:def:autoScalingGroupName/dev-asg"),
						HealthCheckType:         awssdk.String("EC2"),
						AvailabilityZones:       []string{"us-east-1a"},
						LaunchConfigurationName: awssdk.String("dev-lc"),
					},
				},
			}, nil
		},
		DescribeLaunchConfigurationsFunc: func(ctx context.Context, params *autoscaling.DescribeLaunchConfigurationsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error) {
			return &autoscaling.DescribeLaunchConfigurationsOutput{
				LaunchConfigurations: []autoscalingtypes.LaunchConfiguration{
					{
						LaunchConfigurationName:  awssdk.String("dev-lc"),
						AssociatePublicIpAddress: awssdk.Bool(true),
						ImageId:                  awssdk.String("ami-12345"),
						InstanceType:             awssdk.String("t3.micro"),
					},
				},
			}, nil
		},
	}

	collector := NewAutoScalingCollector(mock)
	groups, err := collector.CollectGroups(context.Background())

	require.NoError(t, err)
	require.Len(t, groups, 2)

	assert.Equal(t, "prod-asg", groups[0].GroupName)
	assert.True(t, groups[0].ELBHealthCheck)
	assert.True(t, groups[0].MultiAZ)
	assert.True(t, groups[0].UsesLaunchTemplate)
	assert.False(t, groups[0].AssociatePublicIP)

	assert.Equal(t, "dev-asg", groups[1].GroupName)
	assert.False(t, groups[1].ELBHealthCheck)
	assert.False(t, groups[1].MultiAZ)
	assert.False(t, groups[1].UsesLaunchTemplate)
	assert.True(t, groups[1].AssociatePublicIP)
}

func TestAutoScalingCollector_CollectGroups_Empty(t *testing.T) {
	mock := &MockAutoScalingClient{
		DescribeAutoScalingGroupsFunc: func(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
			return &autoscaling.DescribeAutoScalingGroupsOutput{}, nil
		},
	}

	collector := NewAutoScalingCollector(mock)
	groups, err := collector.CollectGroups(context.Background())

	require.NoError(t, err)
	assert.Empty(t, groups)
}

func TestAutoScalingCollector_CollectGroups_Error(t *testing.T) {
	mock := &MockAutoScalingClient{
		DescribeAutoScalingGroupsFunc: func(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewAutoScalingCollector(mock)
	_, err := collector.CollectGroups(context.Background())
	assert.Error(t, err)
}

func TestAutoScalingCollector_CollectGroups_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockAutoScalingClient{
		DescribeAutoScalingGroupsFunc: func(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
			callCount++
			if callCount == 1 {
				return &autoscaling.DescribeAutoScalingGroupsOutput{
					AutoScalingGroups: []autoscalingtypes.AutoScalingGroup{
						{
							AutoScalingGroupName: awssdk.String("asg-1"),
							AutoScalingGroupARN:  awssdk.String("arn:aws:autoscaling:us-east-1:123:autoScalingGroup:1:autoScalingGroupName/asg-1"),
							HealthCheckType:      awssdk.String("EC2"),
							AvailabilityZones:    []string{"us-east-1a", "us-east-1b"},
						},
					},
					NextToken: awssdk.String("page2"),
				}, nil
			}
			return &autoscaling.DescribeAutoScalingGroupsOutput{
				AutoScalingGroups: []autoscalingtypes.AutoScalingGroup{
					{
						AutoScalingGroupName: awssdk.String("asg-2"),
						AutoScalingGroupARN:  awssdk.String("arn:aws:autoscaling:us-east-1:123:autoScalingGroup:2:autoScalingGroupName/asg-2"),
						HealthCheckType:      awssdk.String("ELB"),
						AvailabilityZones:    []string{"us-east-1a"},
					},
				},
			}, nil
		},
	}

	collector := NewAutoScalingCollector(mock)
	groups, err := collector.CollectGroups(context.Background())

	require.NoError(t, err)
	require.Len(t, groups, 2)
	assert.Equal(t, "asg-1", groups[0].GroupName)
	assert.Equal(t, "asg-2", groups[1].GroupName)
	assert.Equal(t, 2, callCount)
}

func TestAutoScalingCollector_LaunchConfigError_FailSafe(t *testing.T) {
	mock := &MockAutoScalingClient{
		DescribeAutoScalingGroupsFunc: func(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
			return &autoscaling.DescribeAutoScalingGroupsOutput{
				AutoScalingGroups: []autoscalingtypes.AutoScalingGroup{
					{
						AutoScalingGroupName:    awssdk.String("test-asg"),
						AutoScalingGroupARN:     awssdk.String("arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/test-asg"),
						HealthCheckType:         awssdk.String("EC2"),
						AvailabilityZones:       []string{"us-east-1a"},
						LaunchConfigurationName: awssdk.String("some-lc"),
					},
				},
			}, nil
		},
		DescribeLaunchConfigurationsFunc: func(ctx context.Context, params *autoscaling.DescribeLaunchConfigurationsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewAutoScalingCollector(mock)
	groups, err := collector.CollectGroups(context.Background())

	require.NoError(t, err, "should not fail when launch configuration query fails")
	require.Len(t, groups, 1)
	assert.False(t, groups[0].AssociatePublicIP, "public IP should default to false on error")
}

func TestAutoScalingCollector_CollectEvidence(t *testing.T) {
	mock := &MockAutoScalingClient{
		DescribeAutoScalingGroupsFunc: func(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
			return &autoscaling.DescribeAutoScalingGroupsOutput{
				AutoScalingGroups: []autoscalingtypes.AutoScalingGroup{
					{
						AutoScalingGroupName: awssdk.String("ev-asg"),
						AutoScalingGroupARN:  awssdk.String("arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/ev-asg"),
						HealthCheckType:      awssdk.String("ELB"),
						AvailabilityZones:    []string{"us-east-1a", "us-east-1b"},
					},
				},
			}, nil
		},
	}

	collector := NewAutoScalingCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:autoscaling:group", ev[0].ResourceType)
	assert.Equal(t, "123456789012", ev[0].Metadata.AccountID)
}

func TestAutoScalingGroup_ToEvidence(t *testing.T) {
	group := &AutoScalingGroup{
		GroupName:          "prod-asg",
		ARN:                "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/prod-asg",
		ELBHealthCheck:     true,
		MultiAZ:            true,
		UsesLaunchTemplate: true,
	}
	ev := group.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:autoscaling:group", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
