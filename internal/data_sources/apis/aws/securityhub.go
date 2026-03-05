package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// SecurityHubClient defines the interface for Security Hub operations.
type SecurityHubClient interface {
	DescribeHub(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
}

// SecurityHubStatus represents the Security Hub status.
type SecurityHubStatus struct {
	Enabled bool   `json:"enabled"`
	HubARN  string `json:"hub_arn,omitempty"`
	Region  string `json:"region"`
}

// ToEvidence converts a SecurityHubStatus to Evidence.
func (s *SecurityHubStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:securityhub:%s:%s:hub/default", s.Region, accountID)
	ev := evidence.New("aws", "aws:securityhub:hub", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// SecurityHubCollector collects Security Hub status.
type SecurityHubCollector struct {
	client SecurityHubClient
	region string
}

// NewSecurityHubCollector creates a new Security Hub collector.
func NewSecurityHubCollector(client SecurityHubClient, region string) *SecurityHubCollector {
	return &SecurityHubCollector{client: client, region: region}
}

// CollectStatus retrieves Security Hub status.
func (c *SecurityHubCollector) CollectStatus(ctx context.Context) (*SecurityHubStatus, error) {
	status := &SecurityHubStatus{Region: c.region}

	output, err := c.client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		// Not enabled or no access
		return status, nil
	}

	if output.HubArn != nil {
		status.Enabled = true
		status.HubARN = *output.HubArn
	}

	return status, nil
}

// CollectEvidence collects Security Hub status as evidence.
func (c *SecurityHubCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
