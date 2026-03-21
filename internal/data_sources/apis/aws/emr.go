package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// EMRClient defines the interface for EMR operations.
type EMRClient interface {
	ListClusters(ctx context.Context, params *emr.ListClustersInput, optFns ...func(*emr.Options)) (*emr.ListClustersOutput, error)
	DescribeCluster(ctx context.Context, params *emr.DescribeClusterInput, optFns ...func(*emr.Options)) (*emr.DescribeClusterOutput, error)
	GetBlockPublicAccessConfiguration(ctx context.Context, params *emr.GetBlockPublicAccessConfigurationInput, optFns ...func(*emr.Options)) (*emr.GetBlockPublicAccessConfigurationOutput, error)
}

// EMRCluster represents an EMR cluster.
type EMRCluster struct {
	Name                string `json:"name"`
	ID                  string `json:"id"`
	ARN                 string `json:"arn"`
	EncryptionAtRest    bool   `json:"encryption_at_rest"`
	EncryptionInTransit bool   `json:"encryption_in_transit"`
	LoggingEnabled      bool   `json:"logging_enabled"`
}

// ToEvidence converts an EMRCluster to Evidence.
func (c *EMRCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck
	ev := evidence.New("aws", "aws:emr:cluster", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EMRBlockPublicAccess represents EMR block public access configuration.
type EMRBlockPublicAccess struct {
	BlockPublicAccess bool   `json:"block_public_access"`
	Region            string `json:"region"`
}

// ToEvidence converts EMRBlockPublicAccess to Evidence.
func (b *EMRBlockPublicAccess) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(b) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:emr::%s:block-public-access", accountID)
	ev := evidence.New("aws", "aws:emr:block-public-access", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EMRCollector collects EMR data.
type EMRCollector struct {
	client EMRClient
}

// NewEMRCollector creates a new EMR collector.
func NewEMRCollector(client EMRClient) *EMRCollector {
	return &EMRCollector{client: client}
}

// CollectClusters retrieves all active EMR clusters.
func (c *EMRCollector) CollectClusters(ctx context.Context) ([]EMRCluster, error) {
	var clusters []EMRCluster
	var marker *string

	for {
		output, err := c.client.ListClusters(ctx, &emr.ListClustersInput{
			Marker:        marker,
			ClusterStates: []emrtypes.ClusterState{emrtypes.ClusterStateRunning, emrtypes.ClusterStateWaiting},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list EMR clusters: %w", err)
		}

		for _, cl := range output.Clusters {
			cluster := EMRCluster{
				Name: awssdk.ToString(cl.Name),
				ID:   awssdk.ToString(cl.Id),
				ARN:  awssdk.ToString(cl.ClusterArn),
			}

			// Get detailed info
			desc, err := c.client.DescribeCluster(ctx, &emr.DescribeClusterInput{
				ClusterId: cl.Id,
			})
			if err == nil && desc.Cluster != nil {
				if desc.Cluster.SecurityConfiguration != nil {
					// Security configuration present indicates encryption is likely configured
					cluster.EncryptionAtRest = true
					cluster.EncryptionInTransit = true
				}
				cluster.LoggingEnabled = awssdk.ToString(desc.Cluster.LogUri) != ""
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

// CollectBlockPublicAccess checks the EMR block public access configuration.
func (c *EMRCollector) CollectBlockPublicAccess(ctx context.Context) (*EMRBlockPublicAccess, error) {
	status := &EMRBlockPublicAccess{}

	output, err := c.client.GetBlockPublicAccessConfiguration(ctx, &emr.GetBlockPublicAccessConfigurationInput{})
	if err != nil {
		return status, nil // Fail-safe
	}

	if output.BlockPublicAccessConfiguration != nil {
		status.BlockPublicAccess = awssdk.ToBool(output.BlockPublicAccessConfiguration.BlockPublicSecurityGroupRules)
	}

	return status, nil
}

// CollectEvidence collects EMR clusters and block public access as evidence.
func (c *EMRCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	clusters, err := c.CollectClusters(ctx)
	if err != nil {
		return nil, err
	}
	for i := range clusters {
		evidenceList = append(evidenceList, clusters[i].ToEvidence(accountID))
	}

	// Block public access (fail-safe)
	bpa, err := c.CollectBlockPublicAccess(ctx)
	if err == nil {
		evidenceList = append(evidenceList, bpa.ToEvidence(accountID))
	}

	return evidenceList, nil
}
