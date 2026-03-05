package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockEKSClient struct {
	ListClustersFunc    func(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeClusterFunc func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
}

func (m *MockEKSClient) ListClusters(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	return m.ListClustersFunc(ctx, params, optFns...)
}

func (m *MockEKSClient) DescribeCluster(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	return m.DescribeClusterFunc(ctx, params, optFns...)
}

func TestEKSCollector_CollectClusters(t *testing.T) {
	mock := &MockEKSClient{
		ListClustersFunc: func(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
			return &eks.ListClustersOutput{Clusters: []string{"prod-cluster"}}, nil
		},
		DescribeClusterFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			return &eks.DescribeClusterOutput{
				Cluster: &ekstypes.Cluster{
					Name:    awssdk.String("prod-cluster"),
					Arn:     awssdk.String("arn:aws:eks:us-east-1:123:cluster/prod-cluster"),
					Version: awssdk.String("1.28"),
					ResourcesVpcConfig: &ekstypes.VpcConfigResponse{
						EndpointPublicAccess: false,
					},
					Logging: &ekstypes.Logging{
						ClusterLogging: []ekstypes.LogSetup{
							{Enabled: awssdk.Bool(true), Types: []ekstypes.LogType{ekstypes.LogTypeApi}},
						},
					},
					EncryptionConfig: []ekstypes.EncryptionConfig{
						{Resources: []string{"secrets"}, Provider: &ekstypes.Provider{KeyArn: awssdk.String("arn:aws:kms:us-east-1:123:key/abc")}},
					},
				},
			}, nil
		},
	}

	collector := NewEKSCollector(mock)
	clusters, err := collector.CollectClusters(context.Background())

	require.NoError(t, err)
	require.Len(t, clusters, 1)
	assert.Equal(t, "prod-cluster", clusters[0].Name)
	assert.False(t, clusters[0].EndpointPublicAccess)
	assert.True(t, clusters[0].LoggingEnabled)
	assert.True(t, clusters[0].SecretsEncryption)
}

func TestEKSCollector_CollectClusters_Insecure(t *testing.T) {
	mock := &MockEKSClient{
		ListClustersFunc: func(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
			return &eks.ListClustersOutput{Clusters: []string{"dev-cluster"}}, nil
		},
		DescribeClusterFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			return &eks.DescribeClusterOutput{
				Cluster: &ekstypes.Cluster{
					Name:    awssdk.String("dev-cluster"),
					Arn:     awssdk.String("arn:aws:eks:us-east-1:123:cluster/dev-cluster"),
					Version: awssdk.String("1.27"),
					ResourcesVpcConfig: &ekstypes.VpcConfigResponse{
						EndpointPublicAccess: true,
					},
				},
			}, nil
		},
	}

	collector := NewEKSCollector(mock)
	clusters, err := collector.CollectClusters(context.Background())

	require.NoError(t, err)
	require.Len(t, clusters, 1)
	assert.True(t, clusters[0].EndpointPublicAccess)
	assert.False(t, clusters[0].LoggingEnabled)
	assert.False(t, clusters[0].SecretsEncryption)
}

func TestEKSCollector_CollectClusters_Error(t *testing.T) {
	mock := &MockEKSClient{
		ListClustersFunc: func(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEKSCollector(mock)
	_, err := collector.CollectClusters(context.Background())
	assert.Error(t, err)
}

func TestEKSCluster_ToEvidence(t *testing.T) {
	cluster := &EKSCluster{Name: "test", ARN: "arn:aws:eks:us-east-1:123:cluster/test"}
	ev := cluster.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:eks:cluster", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
