package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockElastiCacheClient struct {
	DescribeReplicationGroupsFunc func(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
}

func (m *MockElastiCacheClient) DescribeReplicationGroups(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	return m.DescribeReplicationGroupsFunc(ctx, params, optFns...)
}

func TestElastiCacheCollector_CollectReplicationGroups(t *testing.T) {
	mock := &MockElastiCacheClient{
		DescribeReplicationGroupsFunc: func(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
			return &elasticache.DescribeReplicationGroupsOutput{
				ReplicationGroups: []ectypes.ReplicationGroup{
					{
						ReplicationGroupId:     awssdk.String("prod-redis"),
						ARN:                    awssdk.String("arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis"),
						AtRestEncryptionEnabled: awssdk.Bool(true),
						TransitEncryptionEnabled: awssdk.Bool(true),
						AuthTokenEnabled:        awssdk.Bool(true),
					},
					{
						ReplicationGroupId:     awssdk.String("dev-redis"),
						ARN:                    awssdk.String("arn:aws:elasticache:us-east-1:123:replicationgroup:dev-redis"),
						AtRestEncryptionEnabled: awssdk.Bool(false),
						TransitEncryptionEnabled: awssdk.Bool(false),
						AuthTokenEnabled:        awssdk.Bool(false),
					},
				},
			}, nil
		},
	}

	collector := NewElastiCacheCollector(mock)
	clusters, err := collector.CollectReplicationGroups(context.Background())

	require.NoError(t, err)
	require.Len(t, clusters, 2)

	assert.Equal(t, "prod-redis", clusters[0].ReplicationGroupID)
	assert.True(t, clusters[0].AtRestEncryption)
	assert.True(t, clusters[0].TransitEncryption)
	assert.True(t, clusters[0].AuthTokenEnabled)

	assert.Equal(t, "dev-redis", clusters[1].ReplicationGroupID)
	assert.False(t, clusters[1].AtRestEncryption)
	assert.False(t, clusters[1].TransitEncryption)
}

func TestElastiCacheCollector_NoGroups(t *testing.T) {
	mock := &MockElastiCacheClient{
		DescribeReplicationGroupsFunc: func(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
			return &elasticache.DescribeReplicationGroupsOutput{
				ReplicationGroups: []ectypes.ReplicationGroup{},
			}, nil
		},
	}

	collector := NewElastiCacheCollector(mock)
	clusters, err := collector.CollectReplicationGroups(context.Background())

	require.NoError(t, err)
	assert.Empty(t, clusters)
}

func TestElastiCacheCollector_Error(t *testing.T) {
	mock := &MockElastiCacheClient{
		DescribeReplicationGroupsFunc: func(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewElastiCacheCollector(mock)
	_, err := collector.CollectReplicationGroups(context.Background())
	assert.Error(t, err)
}

func TestElastiCacheCollector_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockElastiCacheClient{
		DescribeReplicationGroupsFunc: func(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
			callCount++
			if callCount == 1 {
				return &elasticache.DescribeReplicationGroupsOutput{
					ReplicationGroups: []ectypes.ReplicationGroup{
						{
							ReplicationGroupId: awssdk.String("rg-1"),
							ARN:                awssdk.String("arn:aws:elasticache:us-east-1:123:replicationgroup:rg-1"),
						},
					},
					Marker: awssdk.String("page2"),
				}, nil
			}
			return &elasticache.DescribeReplicationGroupsOutput{
				ReplicationGroups: []ectypes.ReplicationGroup{
					{
						ReplicationGroupId: awssdk.String("rg-2"),
						ARN:                awssdk.String("arn:aws:elasticache:us-east-1:123:replicationgroup:rg-2"),
					},
				},
			}, nil
		},
	}

	collector := NewElastiCacheCollector(mock)
	clusters, err := collector.CollectReplicationGroups(context.Background())

	require.NoError(t, err)
	assert.Len(t, clusters, 2)
	assert.Equal(t, 2, callCount)
}

func TestElastiCacheCollector_NilFields(t *testing.T) {
	mock := &MockElastiCacheClient{
		DescribeReplicationGroupsFunc: func(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
			return &elasticache.DescribeReplicationGroupsOutput{
				ReplicationGroups: []ectypes.ReplicationGroup{
					{
						ReplicationGroupId:      awssdk.String("minimal"),
						ARN:                     awssdk.String("arn:aws:elasticache:us-east-1:123:replicationgroup:minimal"),
						AtRestEncryptionEnabled: nil,
						TransitEncryptionEnabled: nil,
						AuthTokenEnabled:         nil,
					},
				},
			}, nil
		},
	}

	collector := NewElastiCacheCollector(mock)
	clusters, err := collector.CollectReplicationGroups(context.Background())

	require.NoError(t, err)
	require.Len(t, clusters, 1)
	assert.False(t, clusters[0].AtRestEncryption)
	assert.False(t, clusters[0].TransitEncryption)
	assert.False(t, clusters[0].AuthTokenEnabled)
}

func TestElastiCacheCluster_ToEvidence(t *testing.T) {
	cluster := &ElastiCacheCluster{
		ReplicationGroupID: "prod-redis",
		ARN:                "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis",
		AtRestEncryption:   true,
	}
	ev := cluster.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:elasticache:replication_group", ev.ResourceType)
	assert.Equal(t, "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis", ev.ResourceID)
	assert.NotEmpty(t, ev.Hash)
}
