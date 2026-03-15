package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// GuardDutyClient defines the interface for GuardDuty operations.
type GuardDutyClient interface {
	ListDetectors(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetDetector(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
}

// GuardDutyStatus represents the GuardDuty detector status.
type GuardDutyStatus struct {
	Enabled      bool   `json:"enabled"`
	DetectorID   string `json:"detector_id,omitempty"`
	Status       string `json:"status,omitempty"`
	DetectorCount int   `json:"detector_count"`
	Region       string `json:"region"`
}

// ToEvidence converts a GuardDutyStatus to Evidence.
func (g *GuardDutyStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(g) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("arn:aws:guardduty:%s:%s:detector", g.Region, accountID)
	ev := evidence.New("aws", "aws:guardduty:detector", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// GuardDutyCollector collects GuardDuty status.
type GuardDutyCollector struct {
	client GuardDutyClient
	region string
}

// NewGuardDutyCollector creates a new GuardDuty collector.
func NewGuardDutyCollector(client GuardDutyClient, region string) *GuardDutyCollector {
	return &GuardDutyCollector{client: client, region: region}
}

// CollectStatus retrieves GuardDuty detector status.
func (c *GuardDutyCollector) CollectStatus(ctx context.Context) (*GuardDutyStatus, error) {
	status := &GuardDutyStatus{Region: c.region}

	output, err := c.client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return status, nil //nolint:nilerr // GuardDuty may not be available in all regions
	}

	status.DetectorCount = len(output.DetectorIds)
	if len(output.DetectorIds) == 0 {
		status.Enabled = false
		return status, nil
	}

	// Get first detector details
	detectorID := output.DetectorIds[0]
	status.DetectorID = detectorID

	det, err := c.client.GetDetector(ctx, &guardduty.GetDetectorInput{
		DetectorId: awssdk.String(detectorID),
	})
	if err != nil {
		status.Enabled = false
		return status, nil //nolint:nilerr // fail-safe: treat detector query failure as disabled
	}

	status.Status = string(det.Status)
	status.Enabled = det.Status == "ENABLED"

	return status, nil
}

// CollectEvidence collects GuardDuty status as evidence.
func (c *GuardDutyCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}

	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
