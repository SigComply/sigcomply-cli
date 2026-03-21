package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ElastiCacheClient defines the interface for ElastiCache operations.
type ElastiCacheClient interface {
	DescribeReplicationGroups(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
}

// ElastiCacheCluster represents an ElastiCache replication group.
type ElastiCacheCluster struct {
	ReplicationGroupID       string `json:"replication_group_id"`
	ARN                      string `json:"arn"`
	AtRestEncryption         bool   `json:"at_rest_encryption"`
	TransitEncryption        bool   `json:"transit_encryption"`
	AuthTokenEnabled         bool   `json:"auth_token_enabled"`
	AutomaticFailoverEnabled bool   `json:"automatic_failover_enabled"`
	MultiAZEnabled           bool   `json:"multi_az_enabled"`
	SnapshotRetentionLimit   int    `json:"snapshot_retention_limit"`
	AutoMinorVersionUpgrade  bool   `json:"auto_minor_version_upgrade"`
}

// ToEvidence converts an ElastiCacheCluster to Evidence.
func (c *ElastiCacheCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := c.ARN
	if resourceID == "" {
		resourceID = fmt.Sprintf("elasticache:%s", c.ReplicationGroupID)
	}
	ev := evidence.New("aws", "aws:elasticache:replication_group", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ElastiCacheCollector collects ElastiCache replication group data.
type ElastiCacheCollector struct {
	client ElastiCacheClient
}

// NewElastiCacheCollector creates a new ElastiCache collector.
func NewElastiCacheCollector(client ElastiCacheClient) *ElastiCacheCollector {
	return &ElastiCacheCollector{client: client}
}

// CollectReplicationGroups retrieves all ElastiCache replication groups.
func (c *ElastiCacheCollector) CollectReplicationGroups(ctx context.Context) ([]ElastiCacheCluster, error) {
	var clusters []ElastiCacheCluster
	var marker *string

	for {
		output, err := c.client.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe ElastiCache replication groups: %w", err)
		}

		for i := range output.ReplicationGroups {
			rg := &output.ReplicationGroups[i]
			cluster := ElastiCacheCluster{
				ReplicationGroupID:       awssdk.ToString(rg.ReplicationGroupId),
				ARN:                      awssdk.ToString(rg.ARN),
				AtRestEncryption:         awssdk.ToBool(rg.AtRestEncryptionEnabled),
				TransitEncryption:        awssdk.ToBool(rg.TransitEncryptionEnabled),
				AuthTokenEnabled:         awssdk.ToBool(rg.AuthTokenEnabled),
				AutomaticFailoverEnabled: string(rg.AutomaticFailover) == statusEnabledLower,
				MultiAZEnabled:           string(rg.MultiAZ) == statusEnabledLower,
				SnapshotRetentionLimit:   int(awssdk.ToInt32(rg.SnapshotRetentionLimit)),
			}
			clusters = append(clusters, cluster)
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return clusters, nil
}

// CollectEvidence collects ElastiCache replication groups as evidence.
func (c *ElastiCacheCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	clusters, err := c.CollectReplicationGroups(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(clusters))
	for i := range clusters {
		evidenceList = append(evidenceList, clusters[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
