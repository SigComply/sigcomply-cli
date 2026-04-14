package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// RedshiftClient defines the interface for Redshift operations.
type RedshiftClient interface {
	DescribeClusters(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
	DescribeLoggingStatus(ctx context.Context, params *redshift.DescribeLoggingStatusInput, optFns ...func(*redshift.Options)) (*redshift.DescribeLoggingStatusOutput, error)
	DescribeClusterParameters(ctx context.Context, params *redshift.DescribeClusterParametersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClusterParametersOutput, error)
}

// RedshiftCluster represents a Redshift cluster.
type RedshiftCluster struct {
	ClusterID                  string `json:"cluster_id"`
	ARN                        string `json:"arn"`
	Encrypted                  bool   `json:"encrypted"`
	PubliclyAccessible         bool   `json:"publicly_accessible"`
	LoggingEnabled             bool   `json:"logging_enabled"`
	KMSKeyID                   string `json:"kms_key_id,omitempty"`
	RequireSSL                 bool   `json:"require_ssl"`
	AutomatedSnapshotRetention int    `json:"automated_snapshot_retention"`
	MasterUsername             string `json:"master_username,omitempty"`
	EnhancedVPCRouting         bool   `json:"enhanced_vpc_routing"`
}

// ToEvidence converts a RedshiftCluster to Evidence.
func (c *RedshiftCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:redshift:cluster", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// RedshiftCollector collects Redshift cluster data.
type RedshiftCollector struct {
	client RedshiftClient
}

// NewRedshiftCollector creates a new Redshift collector.
func NewRedshiftCollector(client RedshiftClient) *RedshiftCollector {
	return &RedshiftCollector{client: client}
}

// CollectClusters retrieves all Redshift clusters.
func (c *RedshiftCollector) CollectClusters(ctx context.Context) ([]RedshiftCluster, error) {
	var clusters []RedshiftCluster
	var marker *string

	for {
		output, err := c.client.DescribeClusters(ctx, &redshift.DescribeClustersInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
		}

		for i := range output.Clusters {
			cl := &output.Clusters[i]
			cluster := RedshiftCluster{
				ClusterID:          awssdk.ToString(cl.ClusterIdentifier),
				Encrypted:          awssdk.ToBool(cl.Encrypted),
				PubliclyAccessible: awssdk.ToBool(cl.PubliclyAccessible),
			}

			// Build ARN from cluster namespace ARN or construct it
			if cl.ClusterNamespaceArn != nil {
				cluster.ARN = awssdk.ToString(cl.ClusterNamespaceArn)
			}

			if cl.KmsKeyId != nil {
				cluster.KMSKeyID = awssdk.ToString(cl.KmsKeyId)
			}

			cluster.MasterUsername = awssdk.ToString(cl.MasterUsername)
			cluster.EnhancedVPCRouting = awssdk.ToBool(cl.EnhancedVpcRouting)

			if cl.AutomatedSnapshotRetentionPeriod != nil {
				cluster.AutomatedSnapshotRetention = int(*cl.AutomatedSnapshotRetentionPeriod)
			}

			// Check logging status
			c.enrichLoggingStatus(ctx, &cluster)

			// Check SSL requirement
			c.enrichSSLRequirement(ctx, &cluster, cl.ClusterParameterGroups)

			clusters = append(clusters, cluster)
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return clusters, nil
}

// enrichLoggingStatus checks if audit logging is enabled for a cluster.
func (c *RedshiftCollector) enrichLoggingStatus(ctx context.Context, cluster *RedshiftCluster) {
	output, err := c.client.DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{
		ClusterIdentifier: awssdk.String(cluster.ClusterID),
	})
	if err != nil {
		return // Fail-safe
	}

	cluster.LoggingEnabled = awssdk.ToBool(output.LoggingEnabled)
}

// enrichSSLRequirement checks if require_ssl parameter is enabled.
func (c *RedshiftCollector) enrichSSLRequirement(ctx context.Context, cluster *RedshiftCluster, paramGroups []redshifttypes.ClusterParameterGroupStatus) {
	for _, pg := range paramGroups {
		pgName := awssdk.ToString(pg.ParameterGroupName)
		if pgName == "" {
			continue
		}

		output, err := c.client.DescribeClusterParameters(ctx, &redshift.DescribeClusterParametersInput{
			ParameterGroupName: awssdk.String(pgName),
		})
		if err != nil {
			continue // Fail-safe
		}

		for _, param := range output.Parameters {
			if awssdk.ToString(param.ParameterName) == "require_ssl" {
				cluster.RequireSSL = awssdk.ToString(param.ParameterValue) == statusTrue
				return
			}
		}
	}
}

// CollectEvidence collects Redshift clusters as evidence.
func (c *RedshiftCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	clusters, err := c.CollectClusters(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(clusters))
	for i := range clusters {
		evidenceList = append(evidenceList, clusters[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
