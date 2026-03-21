package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// OrganizationsClient defines the interface for Organizations operations.
type OrganizationsClient interface {
	DescribeOrganization(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
}

// OrganizationStatus represents the Organizations status.
type OrganizationStatus struct {
	IsOrganizationMember bool   `json:"is_organization_member"`
	SCPEnabled           bool   `json:"scp_enabled"`
	SCPCount             int    `json:"scp_count"`
}

// ToEvidence converts an OrganizationStatus to Evidence.
func (s *OrganizationStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:organizations::%s:status", accountID)
	ev := evidence.New("aws", "aws:organizations:status", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// OrganizationsCollector collects Organizations status.
type OrganizationsCollector struct {
	client OrganizationsClient
}

// NewOrganizationsCollector creates a new Organizations collector.
func NewOrganizationsCollector(client OrganizationsClient) *OrganizationsCollector {
	return &OrganizationsCollector{client: client}
}

// CollectStatus retrieves Organizations status.
func (c *OrganizationsCollector) CollectStatus(ctx context.Context) (*OrganizationStatus, error) {
	status := &OrganizationStatus{}

	_, err := c.client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		// Not in an organization or no access
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	status.IsOrganizationMember = true

	// Check for SCPs
	output, err := c.client.ListPolicies(ctx, &organizations.ListPoliciesInput{
		Filter: orgtypes.PolicyTypeServiceControlPolicy,
	})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	// Filter out the default FullAWSAccess policy
	for _, p := range output.Policies {
		name := awssdk.ToString(p.Name)
		if name != "FullAWSAccess" {
			status.SCPCount++
		}
	}
	status.SCPEnabled = status.SCPCount > 0

	return status, nil
}

// CollectEvidence collects Organizations status as evidence.
func (c *OrganizationsCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
