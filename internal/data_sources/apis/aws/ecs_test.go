package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockECSClient struct {
	ListClustersFunc     func(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	DescribeClustersFunc func(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error)
}

func (m *MockECSClient) ListClusters(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return m.ListClustersFunc(ctx, params, optFns...)
}

func (m *MockECSClient) DescribeClusters(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
	return m.DescribeClustersFunc(ctx, params, optFns...)
}

func TestECSCollector_CollectClusters(t *testing.T) {
	mock := &MockECSClient{
		ListClustersFunc: func(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
			return &ecs.ListClustersOutput{
				ClusterArns: []string{"arn:aws:ecs:us-east-1:123:cluster/prod"},
			}, nil
		},
		DescribeClustersFunc: func(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
			return &ecs.DescribeClustersOutput{
				Clusters: []ecstypes.Cluster{
					{
						ClusterName: awssdk.String("prod"),
						ClusterArn:  awssdk.String("arn:aws:ecs:us-east-1:123:cluster/prod"),
						Settings: []ecstypes.ClusterSetting{
							{Name: ecstypes.ClusterSettingNameContainerInsights, Value: awssdk.String("enabled")},
						},
					},
				},
			}, nil
		},
	}

	collector := NewECSCollector(mock)
	clusters, err := collector.CollectClusters(context.Background())

	require.NoError(t, err)
	require.Len(t, clusters, 1)
	assert.Equal(t, "prod", clusters[0].Name)
	assert.True(t, clusters[0].ContainerInsightsEnabled)
}

func TestECSCollector_CollectClusters_InsightsDisabled(t *testing.T) {
	mock := &MockECSClient{
		ListClustersFunc: func(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
			return &ecs.ListClustersOutput{ClusterArns: []string{"arn:aws:ecs:us-east-1:123:cluster/dev"}}, nil
		},
		DescribeClustersFunc: func(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
			return &ecs.DescribeClustersOutput{
				Clusters: []ecstypes.Cluster{
					{ClusterName: awssdk.String("dev"), ClusterArn: awssdk.String("arn:aws:ecs:us-east-1:123:cluster/dev"), Settings: []ecstypes.ClusterSetting{}},
				},
			}, nil
		},
	}

	collector := NewECSCollector(mock)
	clusters, err := collector.CollectClusters(context.Background())

	require.NoError(t, err)
	require.Len(t, clusters, 1)
	assert.False(t, clusters[0].ContainerInsightsEnabled)
}

func TestECSCollector_CollectClusters_Error(t *testing.T) {
	mock := &MockECSClient{
		ListClustersFunc: func(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewECSCollector(mock)
	_, err := collector.CollectClusters(context.Background())
	assert.Error(t, err)
}

func TestECSCluster_ToEvidence(t *testing.T) {
	cluster := &ECSCluster{Name: "prod", ARN: "arn:aws:ecs:us-east-1:123:cluster/prod"}
	ev := cluster.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:ecs:cluster", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
