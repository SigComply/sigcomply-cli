package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// MacieClient defines the interface for Macie operations.
type MacieClient interface {
	GetMacieSession(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error)
}

// MacieStatus represents the Macie session status.
type MacieStatus struct {
	Enabled bool   `json:"enabled"`
	Status  string `json:"status,omitempty"`
	Region  string `json:"region"`
}

// ToEvidence converts a MacieStatus to Evidence.
func (m *MacieStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(m) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:macie2:%s:%s:session", m.Region, accountID)
	ev := evidence.New("aws", "aws:macie2:session", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// MacieCollector collects Macie status.
type MacieCollector struct {
	client MacieClient
	region string
}

// NewMacieCollector creates a new Macie collector.
func NewMacieCollector(client MacieClient, region string) *MacieCollector {
	return &MacieCollector{client: client, region: region}
}

// CollectStatus retrieves Macie session status.
func (c *MacieCollector) CollectStatus(ctx context.Context) (*MacieStatus, error) {
	status := &MacieStatus{Region: c.region}

	output, err := c.client.GetMacieSession(ctx, &macie2.GetMacieSessionInput{})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	status.Status = string(output.Status)
	status.Enabled = output.Status == statusEnabled

	return status, nil
}

// CollectEvidence collects Macie status as evidence.
func (c *MacieCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
