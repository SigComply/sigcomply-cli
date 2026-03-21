package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// MSKClient defines the interface for MSK operations.
type MSKClient interface {
	ListClustersV2(ctx context.Context, params *kafka.ListClustersV2Input, optFns ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error)
}

// MSKCluster represents an MSK cluster.
type MSKCluster struct {
	ClusterName           string `json:"cluster_name"`
	ARN                   string `json:"arn"`
	EncryptionInTransit   bool   `json:"encryption_in_transit"`
	PublicAccess          bool   `json:"public_access"`
	AuthenticationEnabled bool   `json:"authentication_enabled"`
	LoggingEnabled        bool   `json:"logging_enabled"`
}

// ToEvidence converts an MSKCluster to Evidence.
func (c *MSKCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:msk:cluster", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// MSKCollector collects MSK cluster data.
type MSKCollector struct {
	client MSKClient
}

// NewMSKCollector creates a new MSK collector.
func NewMSKCollector(client MSKClient) *MSKCollector {
	return &MSKCollector{client: client}
}

// CollectClusters retrieves all MSK clusters.
//nolint:gocyclo // AWS API response mapping requires sequential field extraction
func (c *MSKCollector) CollectClusters(ctx context.Context) ([]MSKCluster, error) {
	var clusters []MSKCluster
	var nextToken *string

	for {
		output, err := c.client.ListClustersV2(ctx, &kafka.ListClustersV2Input{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list MSK clusters: %w", err)
		}

		for _, ci := range output.ClusterInfoList {
			cluster := MSKCluster{
				ClusterName: awssdk.ToString(ci.ClusterName),
				ARN:         awssdk.ToString(ci.ClusterArn),
			}

			// Check provisioned cluster info
			if ci.Provisioned != nil {
				prov := ci.Provisioned

				// Public access
				if prov.BrokerNodeGroupInfo != nil && prov.BrokerNodeGroupInfo.ConnectivityInfo != nil && prov.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess != nil {
					accessType := awssdk.ToString(prov.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type)
					cluster.PublicAccess = accessType != "" && accessType != "DISABLED"
				}

				// Encryption in transit
				if prov.EncryptionInfo != nil && prov.EncryptionInfo.EncryptionInTransit != nil {
					cluster.EncryptionInTransit = prov.EncryptionInfo.EncryptionInTransit.ClientBroker != kafkatypes.ClientBrokerPlaintext
				}

				// Authentication
				if prov.ClientAuthentication != nil {
					auth := prov.ClientAuthentication
					if auth.Sasl != nil {
						if auth.Sasl.Iam != nil && awssdk.ToBool(auth.Sasl.Iam.Enabled) {
							cluster.AuthenticationEnabled = true
						}
						if auth.Sasl.Scram != nil && awssdk.ToBool(auth.Sasl.Scram.Enabled) {
							cluster.AuthenticationEnabled = true
						}
					}
					if auth.Tls != nil && awssdk.ToBool(auth.Tls.Enabled) {
						cluster.AuthenticationEnabled = true
					}
				}

				// Logging
				if prov.LoggingInfo != nil && prov.LoggingInfo.BrokerLogs != nil {
					logs := prov.LoggingInfo.BrokerLogs
					if logs.CloudWatchLogs != nil && awssdk.ToBool(logs.CloudWatchLogs.Enabled) {
						cluster.LoggingEnabled = true
					}
					if logs.S3 != nil && awssdk.ToBool(logs.S3.Enabled) {
						cluster.LoggingEnabled = true
					}
					if logs.Firehose != nil && awssdk.ToBool(logs.Firehose.Enabled) {
						cluster.LoggingEnabled = true
					}
				}
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

// CollectEvidence collects MSK clusters as evidence.
func (c *MSKCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
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
