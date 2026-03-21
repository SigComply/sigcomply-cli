package aws

import (
	"context"
	"encoding/json"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// EKSClient defines the interface for EKS operations.
type EKSClient interface {
	ListClusters(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
}

// EKSCluster represents an EKS cluster with security configuration.
type EKSCluster struct {
	Name                 string `json:"name"`
	ARN                  string `json:"arn"`
	Version              string `json:"version"`
	EndpointPublicAccess bool   `json:"endpoint_public_access"`
	LoggingEnabled       bool   `json:"logging_enabled"`
	SecretsEncryption    bool   `json:"secrets_encryption"`
}

// ToEvidence converts an EKSCluster to Evidence.
func (c *EKSCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck
	ev := evidence.New("aws", "aws:eks:cluster", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EKSCollector collects EKS cluster data.
type EKSCollector struct {
	client EKSClient
}

// NewEKSCollector creates a new EKS collector.
func NewEKSCollector(client EKSClient) *EKSCollector {
	return &EKSCollector{client: client}
}

// CollectClusters retrieves all EKS clusters with their configuration.
//nolint:gocyclo // AWS API response mapping requires sequential field extraction
func (c *EKSCollector) CollectClusters(ctx context.Context) ([]EKSCluster, error) {
	var clusters []EKSCluster
	var nextToken *string

	for {
		listOutput, err := c.client.ListClusters(ctx, &eks.ListClustersInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}

		for _, name := range listOutput.Clusters {
			descOutput, err := c.client.DescribeCluster(ctx, &eks.DescribeClusterInput{
				Name: awssdk.String(name),
			})
			if err != nil {
				continue // Fail-safe per cluster
			}

			cl := descOutput.Cluster
			if cl == nil {
				continue
			}

			cluster := EKSCluster{
				Name:    awssdk.ToString(cl.Name),
				ARN:     awssdk.ToString(cl.Arn),
				Version: awssdk.ToString(cl.Version),
			}

			// Check endpoint access
			if cl.ResourcesVpcConfig != nil {
				cluster.EndpointPublicAccess = cl.ResourcesVpcConfig.EndpointPublicAccess
			}

			// Check logging
			if cl.Logging != nil {
				for _, logSetup := range cl.Logging.ClusterLogging {
					if logSetup.Enabled != nil && *logSetup.Enabled && len(logSetup.Types) > 0 {
						cluster.LoggingEnabled = true
						break
					}
				}
			}

			// Check secrets encryption
			if cl.EncryptionConfig != nil {
				for _, enc := range cl.EncryptionConfig {
					for _, res := range enc.Resources {
						if res == "secrets" {
							cluster.SecretsEncryption = true
						}
					}
				}
			}

			clusters = append(clusters, cluster)
		}

		if listOutput.NextToken == nil {
			break
		}
		nextToken = listOutput.NextToken
	}

	return clusters, nil
}

// CollectEvidence collects EKS clusters as evidence.
func (c *EKSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
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
