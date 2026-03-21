package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// AccountServiceClient defines the interface for AWS Account operations.
type AccountServiceClient interface {
	GetAlternateContact(ctx context.Context, params *account.GetAlternateContactInput, optFns ...func(*account.Options)) (*account.GetAlternateContactOutput, error)
}

// AccountSecurityContact represents the AWS account security contact configuration.
type AccountSecurityContact struct {
	HasSecurityContact bool   `json:"has_security_contact"`
	Region             string `json:"region"`
}

// ToEvidence converts an AccountSecurityContact to Evidence.
func (a *AccountSecurityContact) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(a) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:account::%s:security-contact", accountID)
	ev := evidence.New("aws", "aws:account:security-contact", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// AccountServiceCollector collects AWS Account data.
type AccountServiceCollector struct {
	client AccountServiceClient
}

// NewAccountServiceCollector creates a new Account service collector.
func NewAccountServiceCollector(client AccountServiceClient) *AccountServiceCollector {
	return &AccountServiceCollector{client: client}
}

// CollectSecurityContact checks if a security contact is configured.
func (c *AccountServiceCollector) CollectSecurityContact(ctx context.Context) (*AccountSecurityContact, error) {
	contact := &AccountSecurityContact{}

	output, err := c.client.GetAlternateContact(ctx, &account.GetAlternateContactInput{
		AlternateContactType: accounttypes.AlternateContactTypeSecurity,
	})
	if err != nil {
		return contact, nil // Fail-safe: no security contact
	}

	contact.HasSecurityContact = output.AlternateContact != nil
	return contact, nil
}

// CollectEvidence collects Account security contact as evidence.
func (c *AccountServiceCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	contact, err := c.CollectSecurityContact(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{contact.ToEvidence(accountID)}, nil
}
