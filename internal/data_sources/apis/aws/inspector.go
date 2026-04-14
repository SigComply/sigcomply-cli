package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// InspectorClient defines the interface for Inspector operations.
type InspectorClient interface {
	BatchGetAccountStatus(ctx context.Context, params *inspector2.BatchGetAccountStatusInput, optFns ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error)
}

// InspectorStatus represents the Inspector status.
type InspectorStatus struct {
	Enabled        bool   `json:"enabled"`
	EC2Scanning    bool   `json:"ec2_scanning"`
	ECRScanning    bool   `json:"ecr_scanning"`
	LambdaScanning bool   `json:"lambda_scanning"`
	Region         string `json:"region"`
}

// ToEvidence converts an InspectorStatus to Evidence.
func (s *InspectorStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:inspector2:%s:%s:status", s.Region, accountID)
	ev := evidence.New("aws", "aws:inspector:status", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// InspectorCollector collects Inspector status.
type InspectorCollector struct {
	client InspectorClient
	region string
}

// NewInspectorCollector creates a new Inspector collector.
func NewInspectorCollector(client InspectorClient, region string) *InspectorCollector {
	return &InspectorCollector{client: client, region: region}
}

// CollectStatus retrieves Inspector status.
func (c *InspectorCollector) CollectStatus(ctx context.Context, accountID string) (*InspectorStatus, error) {
	status := &InspectorStatus{Region: c.region}

	output, err := c.client.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{
		AccountIds: []string{accountID},
	})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	if len(output.Accounts) > 0 {
		acct := output.Accounts[0]
		if acct.ResourceState != nil {
			if acct.ResourceState.Ec2 != nil {
				status.EC2Scanning = string(acct.ResourceState.Ec2.Status) == statusEnabled
			}
			if acct.ResourceState.Ecr != nil {
				status.ECRScanning = string(acct.ResourceState.Ecr.Status) == statusEnabled
			}
			if acct.ResourceState.Lambda != nil {
				status.LambdaScanning = string(acct.ResourceState.Lambda.Status) == statusEnabled
			}
		}
		status.Enabled = status.EC2Scanning || status.ECRScanning || status.LambdaScanning
	}

	return status, nil
}

// CollectEvidence collects Inspector status as evidence.
func (c *InspectorCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx, accountID)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
