package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockRedshiftClient struct {
	DescribeClustersFunc          func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
	DescribeLoggingStatusFunc     func(ctx context.Context, params *redshift.DescribeLoggingStatusInput, optFns ...func(*redshift.Options)) (*redshift.DescribeLoggingStatusOutput, error)
	DescribeClusterParametersFunc func(ctx context.Context, params *redshift.DescribeClusterParametersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClusterParametersOutput, error)
}

func (m *MockRedshiftClient) DescribeClusters(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	return m.DescribeClustersFunc(ctx, params, optFns...)
}

func (m *MockRedshiftClient) DescribeLoggingStatus(ctx context.Context, params *redshift.DescribeLoggingStatusInput, optFns ...func(*redshift.Options)) (*redshift.DescribeLoggingStatusOutput, error) {
	if m.DescribeLoggingStatusFunc != nil {
		return m.DescribeLoggingStatusFunc(ctx, params, optFns...)
	}
	return &redshift.DescribeLoggingStatusOutput{LoggingEnabled: awssdk.Bool(false)}, nil
}

func (m *MockRedshiftClient) DescribeClusterParameters(ctx context.Context, params *redshift.DescribeClusterParametersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClusterParametersOutput, error) {
	if m.DescribeClusterParametersFunc != nil {
		return m.DescribeClusterParametersFunc(ctx, params, optFns...)
	}
	return &redshift.DescribeClusterParametersOutput{}, nil
}

func TestRedshiftCollector_CollectClusters(t *testing.T) {
	mock := &MockRedshiftClient{
		DescribeClustersFunc: func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
			return &redshift.DescribeClustersOutput{
				Clusters: []redshifttypes.Cluster{
					{
						ClusterIdentifier:   awssdk.String("prod-cluster"),
						ClusterNamespaceArn: awssdk.String("arn:aws:redshift:us-east-1:123:namespace:prod-cluster"),
						Encrypted:           awssdk.Bool(true),
						PubliclyAccessible:  awssdk.Bool(false),
						KmsKeyId:            awssdk.String("arn:aws:kms:us-east-1:123:key/abc"),
					},
					{
						ClusterIdentifier:   awssdk.String("dev-cluster"),
						ClusterNamespaceArn: awssdk.String("arn:aws:redshift:us-east-1:123:namespace:dev-cluster"),
						Encrypted:           awssdk.Bool(false),
						PubliclyAccessible:  awssdk.Bool(true),
					},
				},
			}, nil
		},
		DescribeLoggingStatusFunc: func(ctx context.Context, params *redshift.DescribeLoggingStatusInput, optFns ...func(*redshift.Options)) (*redshift.DescribeLoggingStatusOutput, error) {
			if awssdk.ToString(params.ClusterIdentifier) == "prod-cluster" {
				return &redshift.DescribeLoggingStatusOutput{LoggingEnabled: awssdk.Bool(true)}, nil
			}
			return &redshift.DescribeLoggingStatusOutput{LoggingEnabled: awssdk.Bool(false)}, nil
		},
	}

	collector := NewRedshiftCollector(mock)
	clusters, err := collector.CollectClusters(context.Background())

	require.NoError(t, err)
	require.Len(t, clusters, 2)

	assert.Equal(t, "prod-cluster", clusters[0].ClusterID)
	assert.True(t, clusters[0].Encrypted)
	assert.False(t, clusters[0].PubliclyAccessible)
	assert.True(t, clusters[0].LoggingEnabled)

	assert.Equal(t, "dev-cluster", clusters[1].ClusterID)
	assert.False(t, clusters[1].Encrypted)
	assert.True(t, clusters[1].PubliclyAccessible)
	assert.False(t, clusters[1].LoggingEnabled)
}

func TestRedshiftCollector_CollectClusters_Empty(t *testing.T) {
	mock := &MockRedshiftClient{
		DescribeClustersFunc: func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
			return &redshift.DescribeClustersOutput{Clusters: []redshifttypes.Cluster{}}, nil
		},
	}

	collector := NewRedshiftCollector(mock)
	clusters, err := collector.CollectClusters(context.Background())

	require.NoError(t, err)
	assert.Empty(t, clusters)
}

func TestRedshiftCollector_CollectClusters_Error(t *testing.T) {
	mock := &MockRedshiftClient{
		DescribeClustersFunc: func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewRedshiftCollector(mock)
	_, err := collector.CollectClusters(context.Background())
	assert.Error(t, err)
}

func TestRedshiftCollector_CollectClusters_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockRedshiftClient{
		DescribeClustersFunc: func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
			callCount++
			if callCount == 1 {
				return &redshift.DescribeClustersOutput{
					Clusters: []redshifttypes.Cluster{
						{
							ClusterIdentifier:   awssdk.String("cluster-1"),
							ClusterNamespaceArn: awssdk.String("arn:aws:redshift:us-east-1:123:namespace:cluster-1"),
							Encrypted:           awssdk.Bool(true),
							PubliclyAccessible:  awssdk.Bool(false),
						},
					},
					Marker: awssdk.String("page2"),
				}, nil
			}
			return &redshift.DescribeClustersOutput{
				Clusters: []redshifttypes.Cluster{
					{
						ClusterIdentifier:   awssdk.String("cluster-2"),
						ClusterNamespaceArn: awssdk.String("arn:aws:redshift:us-east-1:123:namespace:cluster-2"),
						Encrypted:           awssdk.Bool(false),
						PubliclyAccessible:  awssdk.Bool(true),
					},
				},
			}, nil
		},
	}

	collector := NewRedshiftCollector(mock)
	clusters, err := collector.CollectClusters(context.Background())

	require.NoError(t, err)
	require.Len(t, clusters, 2)
	assert.Equal(t, "cluster-1", clusters[0].ClusterID)
	assert.Equal(t, "cluster-2", clusters[1].ClusterID)
	assert.Equal(t, 2, callCount)
}

func TestRedshiftCollector_LoggingStatusError_FailSafe(t *testing.T) {
	mock := &MockRedshiftClient{
		DescribeClustersFunc: func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
			return &redshift.DescribeClustersOutput{
				Clusters: []redshifttypes.Cluster{
					{
						ClusterIdentifier:   awssdk.String("test-cluster"),
						ClusterNamespaceArn: awssdk.String("arn:aws:redshift:us-east-1:123:namespace:test-cluster"),
						Encrypted:           awssdk.Bool(true),
						PubliclyAccessible:  awssdk.Bool(false),
					},
				},
			}, nil
		},
		DescribeLoggingStatusFunc: func(ctx context.Context, params *redshift.DescribeLoggingStatusInput, optFns ...func(*redshift.Options)) (*redshift.DescribeLoggingStatusOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewRedshiftCollector(mock)
	clusters, err := collector.CollectClusters(context.Background())

	require.NoError(t, err, "should not fail when logging status query fails")
	require.Len(t, clusters, 1)
	assert.False(t, clusters[0].LoggingEnabled, "logging should default to false on error")
}

func TestRedshiftCollector_CollectEvidence(t *testing.T) {
	mock := &MockRedshiftClient{
		DescribeClustersFunc: func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
			return &redshift.DescribeClustersOutput{
				Clusters: []redshifttypes.Cluster{
					{
						ClusterIdentifier:   awssdk.String("ev-cluster"),
						ClusterNamespaceArn: awssdk.String("arn:aws:redshift:us-east-1:123:namespace:ev-cluster"),
						Encrypted:           awssdk.Bool(true),
						PubliclyAccessible:  awssdk.Bool(false),
					},
				},
			}, nil
		},
	}

	collector := NewRedshiftCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:redshift:cluster", ev[0].ResourceType)
	assert.Equal(t, "123456789012", ev[0].Metadata.AccountID)
}

func TestRedshiftCluster_ToEvidence(t *testing.T) {
	cluster := &RedshiftCluster{
		ClusterID: "prod-cluster",
		ARN:       "arn:aws:redshift:us-east-1:123:namespace:prod-cluster",
		Encrypted: true,
	}
	ev := cluster.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:redshift:cluster", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
