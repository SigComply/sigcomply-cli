package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// NetworkFirewallClient defines the interface for Network Firewall operations.
type NetworkFirewallClient interface {
	ListFirewalls(ctx context.Context, params *networkfirewall.ListFirewallsInput, optFns ...func(*networkfirewall.Options)) (*networkfirewall.ListFirewallsOutput, error)
	DescribeFirewall(ctx context.Context, params *networkfirewall.DescribeFirewallInput, optFns ...func(*networkfirewall.Options)) (*networkfirewall.DescribeFirewallOutput, error)
	DescribeLoggingConfiguration(ctx context.Context, params *networkfirewall.DescribeLoggingConfigurationInput, optFns ...func(*networkfirewall.Options)) (*networkfirewall.DescribeLoggingConfigurationOutput, error)
}

// NetworkFirewallStatus represents a Network Firewall.
type NetworkFirewallStatus struct {
	FirewallName       string `json:"firewall_name"`
	ARN                string `json:"arn"`
	LoggingEnabled     bool   `json:"logging_enabled"`
	DeletionProtection bool   `json:"deletion_protection"`
	HasFirewallPolicy  bool   `json:"has_firewall_policy"`
}

// ToEvidence converts a NetworkFirewallStatus to Evidence.
func (f *NetworkFirewallStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(f) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:networkfirewall:firewall", f.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// NetworkFirewallCollector collects Network Firewall data.
type NetworkFirewallCollector struct {
	client NetworkFirewallClient
}

// NewNetworkFirewallCollector creates a new Network Firewall collector.
func NewNetworkFirewallCollector(client NetworkFirewallClient) *NetworkFirewallCollector {
	return &NetworkFirewallCollector{client: client}
}

// CollectFirewalls retrieves all Network Firewalls.
func (c *NetworkFirewallCollector) CollectFirewalls(ctx context.Context) ([]NetworkFirewallStatus, error) {
	var firewalls []NetworkFirewallStatus
	var nextToken *string

	for {
		output, err := c.client.ListFirewalls(ctx, &networkfirewall.ListFirewallsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list network firewalls: %w", err)
		}

		for _, fw := range output.Firewalls {
			fwARN := awssdk.ToString(fw.FirewallArn)
			status := NetworkFirewallStatus{
				FirewallName: awssdk.ToString(fw.FirewallName),
				ARN:          fwARN,
			}

			// Get firewall details
			desc, err := c.client.DescribeFirewall(ctx, &networkfirewall.DescribeFirewallInput{
				FirewallArn: awssdk.String(fwARN),
			})
			if err == nil && desc.Firewall != nil {
				// DeleteProtection is a plain bool (not *bool)
				status.DeletionProtection = desc.Firewall.DeleteProtection
				status.HasFirewallPolicy = awssdk.ToString(desc.Firewall.FirewallPolicyArn) != ""
			}

			// Check logging
			logCfg, err := c.client.DescribeLoggingConfiguration(ctx, &networkfirewall.DescribeLoggingConfigurationInput{
				FirewallArn: awssdk.String(fwARN),
			})
			if err == nil && logCfg.LoggingConfiguration != nil {
				status.LoggingEnabled = len(logCfg.LoggingConfiguration.LogDestinationConfigs) > 0
			}

			firewalls = append(firewalls, status)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return firewalls, nil
}

// CollectEvidence collects Network Firewalls as evidence.
func (c *NetworkFirewallCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	firewalls, err := c.CollectFirewalls(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(firewalls))
	for i := range firewalls {
		evidenceList = append(evidenceList, firewalls[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
