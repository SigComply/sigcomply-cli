package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// DAXClient defines the interface for DAX operations.
type DAXClient interface {
	DescribeClusters(ctx context.Context, params *dax.DescribeClustersInput, optFns ...func(*dax.Options)) (*dax.DescribeClustersOutput, error)
}

// DAXCluster represents a DAX cluster.
type DAXCluster struct {
	Name                          string `json:"name"`
	ARN                           string `json:"arn"`
	SSEEnabled                    bool   `json:"sse_enabled"`
	ClusterEndpointEncryptionType string `json:"cluster_endpoint_encryption_type"`
}

// ToEvidence converts a DAXCluster to Evidence.
func (c *DAXCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck
	ev := evidence.New("aws", "aws:dax:cluster", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// DAXCollector collects DAX cluster data.
type DAXCollector struct {
	client DAXClient
}

// NewDAXCollector creates a new DAX collector.
func NewDAXCollector(client DAXClient) *DAXCollector {
	return &DAXCollector{client: client}
}

// CollectClusters retrieves all DAX clusters.
func (c *DAXCollector) CollectClusters(ctx context.Context) ([]DAXCluster, error) {
	var clusters []DAXCluster
	var nextToken *string

	for {
		output, err := c.client.DescribeClusters(ctx, &dax.DescribeClustersInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe DAX clusters: %w", err)
		}

		for i := range output.Clusters {
			cl := &output.Clusters[i]
			cluster := DAXCluster{
				Name:                          awssdk.ToString(cl.ClusterName),
				ARN:                           awssdk.ToString(cl.ClusterArn),
				ClusterEndpointEncryptionType: string(cl.ClusterEndpointEncryptionType),
			}

			if cl.SSEDescription != nil {
				cluster.SSEEnabled = string(cl.SSEDescription.Status) == statusEnabled
			}

			clusters = append(clusters, cluster)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return clusters, nil
}

// CollectEvidence collects DAX clusters as evidence.
func (c *DAXCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
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
