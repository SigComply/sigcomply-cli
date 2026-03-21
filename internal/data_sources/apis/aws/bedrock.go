package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// BedrockClient defines the interface for Bedrock operations.
type BedrockClient interface {
	GetModelInvocationLoggingConfiguration(ctx context.Context, params *bedrock.GetModelInvocationLoggingConfigurationInput, optFns ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error)
}

// BedrockLoggingConfig represents the Bedrock model invocation logging configuration.
type BedrockLoggingConfig struct {
	InvocationLoggingEnabled bool   `json:"invocation_logging_enabled"`
	Region                   string `json:"region"`
}

// ToEvidence converts a BedrockLoggingConfig to Evidence.
func (b *BedrockLoggingConfig) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(b) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:bedrock:%s:%s:logging-config", b.Region, accountID)
	ev := evidence.New("aws", "aws:bedrock:model", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// BedrockCollector collects Bedrock logging configuration data.
type BedrockCollector struct {
	client BedrockClient
	region string
}

// NewBedrockCollector creates a new Bedrock collector.
func NewBedrockCollector(client BedrockClient, region string) *BedrockCollector {
	return &BedrockCollector{client: client, region: region}
}

// CollectLoggingConfig retrieves the Bedrock model invocation logging configuration.
func (c *BedrockCollector) CollectLoggingConfig(ctx context.Context) (*BedrockLoggingConfig, error) {
	config := &BedrockLoggingConfig{Region: c.region}

	output, err := c.client.GetModelInvocationLoggingConfiguration(ctx, &bedrock.GetModelInvocationLoggingConfigurationInput{})
	if err != nil {
		return config, nil // Fail-safe: no logging config means disabled
	}

	if output.LoggingConfig != nil {
		// Logging is enabled if either CloudWatch or S3 destination is configured
		config.InvocationLoggingEnabled = output.LoggingConfig.CloudWatchConfig != nil || output.LoggingConfig.S3Config != nil
	}

	return config, nil
}

// CollectEvidence collects Bedrock logging configuration as evidence.
func (c *BedrockCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	config, err := c.CollectLoggingConfig(ctx)
	if err != nil {
		return nil, err
	}

	return []evidence.Evidence{config.ToEvidence(accountID)}, nil
}
