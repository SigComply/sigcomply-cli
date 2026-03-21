package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// SecurityHubClient defines the interface for Security Hub operations.
type SecurityHubClient interface {
	DescribeHub(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
	GetEnabledStandards(ctx context.Context, params *securityhub.GetEnabledStandardsInput, optFns ...func(*securityhub.Options)) (*securityhub.GetEnabledStandardsOutput, error)
}

// SecurityHubStatus represents the Security Hub status.
type SecurityHubStatus struct {
	Enabled bool   `json:"enabled"`
	HubARN  string `json:"hub_arn,omitempty"`
	Region  string `json:"region"`
	HasFSBP bool   `json:"has_fsbp"`
	HasCIS  bool   `json:"has_cis"`
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
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	if output.HubArn != nil {
		status.Enabled = true
		status.HubARN = *output.HubArn
	}

	// Enrich with enabled standards
	c.enrichStandards(ctx, status)

	return status, nil
}

// enrichStandards checks which security standards are enabled.
func (c *SecurityHubCollector) enrichStandards(ctx context.Context, status *SecurityHubStatus) {
	if !status.Enabled {
		return
	}

	output, err := c.client.GetEnabledStandards(ctx, &securityhub.GetEnabledStandardsInput{})
	if err != nil {
		return
	}

	for _, std := range output.StandardsSubscriptions {
		arn := ""
		if std.StandardsArn != nil {
			arn = *std.StandardsArn
		}
		if strings.Contains(arn, "aws-foundational-security-best-practices") || strings.Contains(arn, "standards/aws-foundational") {
			status.HasFSBP = true
		}
		if strings.Contains(arn, "cis-aws-foundations-benchmark") || strings.Contains(arn, "standards/cis") {
			status.HasCIS = true
		}
	}
}

// CollectEvidence collects Security Hub status as evidence.
func (c *SecurityHubCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
