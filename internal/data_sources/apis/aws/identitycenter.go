package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// IdentityCenterClient defines the interface for Identity Center operations.
type IdentityCenterClient interface {
	ListInstances(ctx context.Context, params *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
}

// IdentityCenterStatus represents the IAM Identity Center status.
type IdentityCenterStatus struct {
	Enabled     bool   `json:"enabled"`
	InstanceARN string `json:"instance_arn,omitempty"`
	Region      string `json:"region"`
}

// ToEvidence converts an IdentityCenterStatus to Evidence.
func (s *IdentityCenterStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:sso:%s:%s:status", s.Region, accountID)
	ev := evidence.New("aws", "aws:identitycenter:status", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// IdentityCenterCollector collects Identity Center status.
type IdentityCenterCollector struct {
	client IdentityCenterClient
	region string
}

// NewIdentityCenterCollector creates a new Identity Center collector.
func NewIdentityCenterCollector(client IdentityCenterClient, region string) *IdentityCenterCollector {
	return &IdentityCenterCollector{client: client, region: region}
}

// CollectStatus retrieves Identity Center status.
func (c *IdentityCenterCollector) CollectStatus(ctx context.Context) (*IdentityCenterStatus, error) {
	status := &IdentityCenterStatus{Region: c.region}

	output, err := c.client.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		return status, nil // Fail-safe
	}

	if len(output.Instances) > 0 {
		status.Enabled = true
		status.InstanceARN = awssdk.ToString(output.Instances[0].InstanceArn)
	}

	return status, nil
}

// CollectEvidence collects Identity Center status as evidence.
func (c *IdentityCenterCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
