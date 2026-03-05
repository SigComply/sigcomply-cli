package aws

import (
	"context"
	"encoding/json"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ECSClient defines the interface for ECS operations.
type ECSClient interface {
	ListClusters(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	DescribeClusters(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error)
}

// ECSCluster represents an ECS cluster with security configuration.
type ECSCluster struct {
	Name                     string `json:"name"`
	ARN                      string `json:"arn"`
	ContainerInsightsEnabled bool   `json:"container_insights_enabled"`
}

// ToEvidence converts an ECSCluster to Evidence.
func (c *ECSCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck
	ev := evidence.New("aws", "aws:ecs:cluster", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ECSCollector collects ECS cluster data.
type ECSCollector struct {
	client ECSClient
}

// NewECSCollector creates a new ECS collector.
func NewECSCollector(client ECSClient) *ECSCollector {
	return &ECSCollector{client: client}
}

// CollectClusters retrieves all ECS clusters with their configuration.
func (c *ECSCollector) CollectClusters(ctx context.Context) ([]ECSCluster, error) {
	var clusters []ECSCluster
	var nextToken *string

	for {
		listOutput, err := c.client.ListClusters(ctx, &ecs.ListClustersInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}

		if len(listOutput.ClusterArns) == 0 {
			break
		}

		descOutput, err := c.client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: listOutput.ClusterArns,
			Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldSettings},
		})
		if err != nil {
			return nil, err
		}

		for _, cl := range descOutput.Clusters {
			cluster := ECSCluster{
				Name: awssdk.ToString(cl.ClusterName),
				ARN:  awssdk.ToString(cl.ClusterArn),
			}

			for _, setting := range cl.Settings {
				if string(setting.Name) == "containerInsights" {
					cluster.ContainerInsightsEnabled = awssdk.ToString(setting.Value) == "enabled"
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

// CollectEvidence collects ECS clusters as evidence.
func (c *ECSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
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
