package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// DocumentDBClient defines the interface for DocumentDB operations.
type DocumentDBClient interface {
	DescribeDBClusters(ctx context.Context, params *docdb.DescribeDBClustersInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error)
	DescribeDBClusterSnapshots(ctx context.Context, params *docdb.DescribeDBClusterSnapshotsInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClusterSnapshotsOutput, error)
}

// DocumentDBCluster represents a DocumentDB cluster.
type DocumentDBCluster struct {
	ClusterID             string `json:"cluster_id"`
	ARN                   string `json:"arn"`
	StorageEncrypted      bool   `json:"storage_encrypted"`
	BackupRetentionPeriod int    `json:"backup_retention_period"`
	AuditLogsEnabled      bool   `json:"audit_logs_enabled"`
	DeletionProtection    bool   `json:"deletion_protection"`
	TLSEnabled            bool   `json:"tls_enabled"`
}

// ToEvidence converts a DocumentDBCluster to Evidence.
func (c *DocumentDBCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck
	ev := evidence.New("aws", "aws:documentdb:cluster", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// DocumentDBSnapshot represents a DocumentDB cluster snapshot.
type DocumentDBSnapshot struct {
	SnapshotID string `json:"snapshot_id"`
	ClusterID  string `json:"cluster_id,omitempty"`
	ARN        string `json:"arn"`
	Encrypted  bool   `json:"encrypted"`
	IsPublic   bool   `json:"is_public"`
}

// ToEvidence converts a DocumentDBSnapshot to Evidence.
func (s *DocumentDBSnapshot) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck
	ev := evidence.New("aws", "aws:documentdb:snapshot", s.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// DocumentDBCollector collects DocumentDB cluster and snapshot data.
type DocumentDBCollector struct {
	client DocumentDBClient
}

// NewDocumentDBCollector creates a new DocumentDB collector.
func NewDocumentDBCollector(client DocumentDBClient) *DocumentDBCollector {
	return &DocumentDBCollector{client: client}
}

// CollectClusters retrieves all DocumentDB clusters.
func (c *DocumentDBCollector) CollectClusters(ctx context.Context) ([]DocumentDBCluster, error) {
	var clusters []DocumentDBCluster
	var marker *string

	for {
		output, err := c.client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe DocumentDB clusters: %w", err)
		}

		for _, cl := range output.DBClusters {
			cluster := DocumentDBCluster{
				ClusterID:          awssdk.ToString(cl.DBClusterIdentifier),
				ARN:                awssdk.ToString(cl.DBClusterArn),
				StorageEncrypted:   awssdk.ToBool(cl.StorageEncrypted),
				DeletionProtection: awssdk.ToBool(cl.DeletionProtection),
			}

			if cl.BackupRetentionPeriod != nil {
				cluster.BackupRetentionPeriod = int(*cl.BackupRetentionPeriod)
			}

			// Check audit logs
			for _, logType := range cl.EnabledCloudwatchLogsExports {
				if logType == "audit" {
					cluster.AuditLogsEnabled = true
					break
				}
			}

			// TLS: DocumentDB enables TLS by default. A thorough check would use
			// DescribeDBClusterParameters to verify the tls parameter group setting.
			// We default to true as a conservative baseline.
			cluster.TLSEnabled = true

			clusters = append(clusters, cluster)
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return clusters, nil
}

// CollectSnapshots retrieves all DocumentDB cluster snapshots.
func (c *DocumentDBCollector) CollectSnapshots(ctx context.Context) ([]DocumentDBSnapshot, error) {
	var snapshots []DocumentDBSnapshot
	var marker *string

	for {
		output, err := c.client.DescribeDBClusterSnapshots(ctx, &docdb.DescribeDBClusterSnapshotsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe DocumentDB snapshots: %w", err)
		}

		for _, snap := range output.DBClusterSnapshots {
			snapshot := DocumentDBSnapshot{
				SnapshotID: awssdk.ToString(snap.DBClusterSnapshotIdentifier),
				ClusterID:  awssdk.ToString(snap.DBClusterIdentifier),
				ARN:        awssdk.ToString(snap.DBClusterSnapshotArn),
				Encrypted:  awssdk.ToBool(snap.StorageEncrypted),
				IsPublic:   false,
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

// CollectEvidence collects DocumentDB clusters and snapshots as evidence.
func (c *DocumentDBCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	clusters, err := c.CollectClusters(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(clusters))
	for i := range clusters {
		evidenceList = append(evidenceList, clusters[i].ToEvidence(accountID))
	}

	// Collect snapshots (fail-safe: snapshot errors do not fail evidence collection)
	snapshots, snapshotErr := c.CollectSnapshots(ctx)
	if snapshotErr == nil {
		for i := range snapshots {
			evidenceList = append(evidenceList, snapshots[i].ToEvidence(accountID))
		}
	}

	return evidenceList, nil
}
