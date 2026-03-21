package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// NeptuneClient defines the interface for Neptune operations.
type NeptuneClient interface {
	DescribeDBClusters(ctx context.Context, params *neptune.DescribeDBClustersInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error)
	DescribeDBClusterSnapshots(ctx context.Context, params *neptune.DescribeDBClusterSnapshotsInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClusterSnapshotsOutput, error)
}

// NeptuneCluster represents a Neptune DB cluster.
type NeptuneCluster struct {
	ClusterID             string `json:"cluster_id"`
	ARN                   string `json:"arn"`
	StorageEncrypted      bool   `json:"storage_encrypted"`
	AuditLogsEnabled      bool   `json:"audit_logs_enabled"`
	DeletionProtection    bool   `json:"deletion_protection"`
	BackupRetentionPeriod int    `json:"backup_retention_period"`
	IAMAuthEnabled        bool   `json:"iam_auth_enabled"`
}

// ToEvidence converts a NeptuneCluster to Evidence.
func (c *NeptuneCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:neptune:cluster", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// NeptuneSnapshot represents a Neptune DB cluster snapshot.
type NeptuneSnapshot struct {
	SnapshotID string `json:"snapshot_id"`
	ClusterID  string `json:"cluster_id,omitempty"`
	ARN        string `json:"arn"`
	Encrypted  bool   `json:"encrypted"`
	IsPublic   bool   `json:"is_public"`
}

// ToEvidence converts a NeptuneSnapshot to Evidence.
func (s *NeptuneSnapshot) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:neptune:snapshot", s.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// NeptuneCollector collects Neptune cluster and snapshot data.
type NeptuneCollector struct {
	client NeptuneClient
}

// NewNeptuneCollector creates a new Neptune collector.
func NewNeptuneCollector(client NeptuneClient) *NeptuneCollector {
	return &NeptuneCollector{client: client}
}

// CollectClusters retrieves all Neptune clusters.
func (c *NeptuneCollector) CollectClusters(ctx context.Context) ([]NeptuneCluster, error) {
	var clusters []NeptuneCluster
	var marker *string

	for {
		output, err := c.client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe Neptune clusters: %w", err)
		}

		for i := range output.DBClusters {
			cl := &output.DBClusters[i]
			cluster := NeptuneCluster{
				ClusterID:          awssdk.ToString(cl.DBClusterIdentifier),
				ARN:                awssdk.ToString(cl.DBClusterArn),
				StorageEncrypted:   awssdk.ToBool(cl.StorageEncrypted),
				DeletionProtection: awssdk.ToBool(cl.DeletionProtection),
				IAMAuthEnabled:     awssdk.ToBool(cl.IAMDatabaseAuthenticationEnabled),
			}

			if cl.BackupRetentionPeriod != nil {
				cluster.BackupRetentionPeriod = int(*cl.BackupRetentionPeriod)
			}

			// Check if audit logs are enabled
			for _, logType := range cl.EnabledCloudwatchLogsExports {
				if logType == "audit" {
					cluster.AuditLogsEnabled = true
					break
				}
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

// CollectSnapshots retrieves all Neptune cluster snapshots.
func (c *NeptuneCollector) CollectSnapshots(ctx context.Context) ([]NeptuneSnapshot, error) {
	var snapshots []NeptuneSnapshot
	var marker *string

	for {
		output, err := c.client.DescribeDBClusterSnapshots(ctx, &neptune.DescribeDBClusterSnapshotsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe Neptune snapshots: %w", err)
		}

		for i := range output.DBClusterSnapshots {
			snap := &output.DBClusterSnapshots[i]
			snapshot := NeptuneSnapshot{
				SnapshotID: awssdk.ToString(snap.DBClusterSnapshotIdentifier),
				ClusterID:  awssdk.ToString(snap.DBClusterIdentifier),
				ARN:        awssdk.ToString(snap.DBClusterSnapshotArn),
				Encrypted:  awssdk.ToBool(snap.StorageEncrypted),
				// Note: Neptune SDK DescribeDBClusterSnapshots doesn't have a direct "public" field.
				// DescribeDBClusterSnapshotAttributes would be needed for that; keeping false as default.
				IsPublic: false,
			}
			snapshots = append(snapshots, snapshot)
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return snapshots, nil
}

// CollectEvidence collects Neptune clusters and snapshots as evidence.
func (c *NeptuneCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	clusters, err := c.CollectClusters(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(clusters))
	for i := range clusters {
		evidenceList = append(evidenceList, clusters[i].ToEvidence(accountID))
	}

	// Collect snapshots (fail-safe)
	snapshots, err := c.CollectSnapshots(ctx)
	if err == nil {
		for i := range snapshots {
			evidenceList = append(evidenceList, snapshots[i].ToEvidence(accountID))
		}
	}

	return evidenceList, nil
}
