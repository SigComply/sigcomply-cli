package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// MQClient defines the interface for Amazon MQ operations.
type MQClient interface {
	ListBrokers(ctx context.Context, params *mq.ListBrokersInput, optFns ...func(*mq.Options)) (*mq.ListBrokersOutput, error)
	DescribeBroker(ctx context.Context, params *mq.DescribeBrokerInput, optFns ...func(*mq.Options)) (*mq.DescribeBrokerOutput, error)
}

// MQBroker represents an Amazon MQ broker.
type MQBroker struct {
	BrokerName              string `json:"broker_name"`
	ARN                     string `json:"arn"`
	AuditLogsEnabled        bool   `json:"audit_logs_enabled"`
	AutoMinorVersionUpgrade bool   `json:"auto_minor_version_upgrade"`
	DeploymentMode          string `json:"deployment_mode"`
}

// ToEvidence converts an MQBroker to Evidence.
func (b *MQBroker) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(b) //nolint:errcheck
	ev := evidence.New("aws", "aws:mq:broker", b.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// MQCollector collects Amazon MQ broker data.
type MQCollector struct {
	client MQClient
}

// NewMQCollector creates a new Amazon MQ collector.
func NewMQCollector(client MQClient) *MQCollector {
	return &MQCollector{client: client}
}

// CollectBrokers retrieves all Amazon MQ brokers.
func (c *MQCollector) CollectBrokers(ctx context.Context) ([]MQBroker, error) {
	var brokers []MQBroker
	var nextToken *string

	for {
		output, err := c.client.ListBrokers(ctx, &mq.ListBrokersInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Amazon MQ brokers: %w", err)
		}

		for _, summary := range output.BrokerSummaries {
			brokerID := awssdk.ToString(summary.BrokerId)
			if brokerID == "" {
				continue
			}

			broker := MQBroker{
				BrokerName: awssdk.ToString(summary.BrokerName),
				ARN:        awssdk.ToString(summary.BrokerArn),
			}

			// Enrich with full broker details
			c.enrichBrokerDetails(ctx, &broker, brokerID)

			brokers = append(brokers, broker)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return brokers, nil
}

// enrichBrokerDetails fetches full broker details including logging and upgrade settings.
func (c *MQCollector) enrichBrokerDetails(ctx context.Context, broker *MQBroker, brokerID string) {
	output, err := c.client.DescribeBroker(ctx, &mq.DescribeBrokerInput{
		BrokerId: awssdk.String(brokerID),
	})
	if err != nil {
		return // Fail-safe
	}

	if output.Logs != nil && output.Logs.Audit != nil {
		broker.AuditLogsEnabled = awssdk.ToBool(output.Logs.Audit)
	}

	broker.AutoMinorVersionUpgrade = awssdk.ToBool(output.AutoMinorVersionUpgrade)
	broker.DeploymentMode = string(output.DeploymentMode)
}

// CollectEvidence collects Amazon MQ brokers as evidence.
func (c *MQCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	brokers, err := c.CollectBrokers(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(brokers))
	for i := range brokers {
		evidenceList = append(evidenceList, brokers[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
