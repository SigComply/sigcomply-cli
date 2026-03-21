package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockAthenaClient struct {
	ListWorkGroupsFunc func(ctx context.Context, params *athena.ListWorkGroupsInput, optFns ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error)
	GetWorkGroupFunc   func(ctx context.Context, params *athena.GetWorkGroupInput, optFns ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error)
}

func (m *MockAthenaClient) ListWorkGroups(ctx context.Context, params *athena.ListWorkGroupsInput, optFns ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error) {
	return m.ListWorkGroupsFunc(ctx, params, optFns...)
}

func (m *MockAthenaClient) GetWorkGroup(ctx context.Context, params *athena.GetWorkGroupInput, optFns ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error) {
	if m.GetWorkGroupFunc != nil {
		return m.GetWorkGroupFunc(ctx, params, optFns...)
	}
	return &athena.GetWorkGroupOutput{}, nil
}

func TestAthenaCollector_CollectWorkgroups(t *testing.T) {
	mock := &MockAthenaClient{
		ListWorkGroupsFunc: func(ctx context.Context, params *athena.ListWorkGroupsInput, optFns ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error) {
			return &athena.ListWorkGroupsOutput{
				WorkGroups: []athenatypes.WorkGroupSummary{
					{Name: awssdk.String("primary")},
					{Name: awssdk.String("analytics")},
				},
			}, nil
		},
		GetWorkGroupFunc: func(ctx context.Context, params *athena.GetWorkGroupInput, optFns ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error) {
			metrics := awssdk.ToString(params.WorkGroup) == "primary"
			return &athena.GetWorkGroupOutput{
				WorkGroup: &athenatypes.WorkGroup{
					Name: params.WorkGroup,
					Configuration: &athenatypes.WorkGroupConfiguration{
						PublishCloudWatchMetricsEnabled: awssdk.Bool(metrics),
					},
				},
			}, nil
		},
	}

	collector := NewAthenaCollector(mock)
	workgroups, err := collector.CollectWorkgroups(context.Background())

	require.NoError(t, err)
	require.Len(t, workgroups, 2)

	assert.Equal(t, "primary", workgroups[0].Name)
	assert.True(t, workgroups[0].PublishCloudWatchMetrics)

	assert.Equal(t, "analytics", workgroups[1].Name)
	assert.False(t, workgroups[1].PublishCloudWatchMetrics)
}

func TestAthenaCollector_CollectEvidence(t *testing.T) {
	mock := &MockAthenaClient{
		ListWorkGroupsFunc: func(ctx context.Context, params *athena.ListWorkGroupsInput, optFns ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error) {
			return &athena.ListWorkGroupsOutput{
				WorkGroups: []athenatypes.WorkGroupSummary{
					{Name: awssdk.String("primary")},
				},
			}, nil
		},
		GetWorkGroupFunc: func(ctx context.Context, params *athena.GetWorkGroupInput, optFns ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error) {
			return &athena.GetWorkGroupOutput{
				WorkGroup: &athenatypes.WorkGroup{
					Name: params.WorkGroup,
					Configuration: &athenatypes.WorkGroupConfiguration{
						PublishCloudWatchMetricsEnabled: awssdk.Bool(true),
					},
				},
			}, nil
		},
	}

	collector := NewAthenaCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:athena:workgroup", ev[0].ResourceType)
}
