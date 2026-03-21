package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	daxtypes "github.com/aws/aws-sdk-go-v2/service/dax/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockDAXClient struct {
	DescribeClustersFunc func(ctx context.Context, params *dax.DescribeClustersInput, optFns ...func(*dax.Options)) (*dax.DescribeClustersOutput, error)
}

func (m *MockDAXClient) DescribeClusters(ctx context.Context, params *dax.DescribeClustersInput, optFns ...func(*dax.Options)) (*dax.DescribeClustersOutput, error) {
	return m.DescribeClustersFunc(ctx, params, optFns...)
}

func TestDAXCollector_CollectClusters(t *testing.T) {
	mock := &MockDAXClient{
		DescribeClustersFunc: func(ctx context.Context, params *dax.DescribeClustersInput, optFns ...func(*dax.Options)) (*dax.DescribeClustersOutput, error) {
			return &dax.DescribeClustersOutput{
				Clusters: []daxtypes.Cluster{
					{
						ClusterName:                   awssdk.String("secure-cluster"),
						ClusterArn:                    awssdk.String("arn:aws:dax:us-east-1:123:cache/secure-cluster"),
						SSEDescription:                &daxtypes.SSEDescription{Status: daxtypes.SSEStatusEnabled},
						ClusterEndpointEncryptionType: daxtypes.ClusterEndpointEncryptionTypeTls,
					},
					{
						ClusterName:                   awssdk.String("insecure-cluster"),
						ClusterArn:                    awssdk.String("arn:aws:dax:us-east-1:123:cache/insecure-cluster"),
						SSEDescription:                &daxtypes.SSEDescription{Status: daxtypes.SSEStatusDisabled},
						ClusterEndpointEncryptionType: daxtypes.ClusterEndpointEncryptionTypeNone,
					},
				},
			}, nil
		},
	}

	collector := NewDAXCollector(mock)
	clusters, err := collector.CollectClusters(context.Background())

	require.NoError(t, err)
	require.Len(t, clusters, 2)

	assert.Equal(t, "secure-cluster", clusters[0].Name)
	assert.True(t, clusters[0].SSEEnabled)
	assert.Equal(t, "TLS", clusters[0].ClusterEndpointEncryptionType)

	assert.Equal(t, "insecure-cluster", clusters[1].Name)
	assert.False(t, clusters[1].SSEEnabled)
	assert.Equal(t, "NONE", clusters[1].ClusterEndpointEncryptionType)
}

func TestDAXCollector_CollectEvidence(t *testing.T) {
	mock := &MockDAXClient{
		DescribeClustersFunc: func(ctx context.Context, params *dax.DescribeClustersInput, optFns ...func(*dax.Options)) (*dax.DescribeClustersOutput, error) {
			return &dax.DescribeClustersOutput{
				Clusters: []daxtypes.Cluster{
					{
						ClusterName: awssdk.String("cluster"),
						ClusterArn:  awssdk.String("arn:aws:dax:us-east-1:123:cache/cluster"),
					},
				},
			}, nil
		},
	}

	collector := NewDAXCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:dax:cluster", ev[0].ResourceType)
}
