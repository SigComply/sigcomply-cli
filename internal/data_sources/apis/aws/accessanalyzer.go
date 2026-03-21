package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// AccessAnalyzerClient defines the interface for Access Analyzer operations.
type AccessAnalyzerClient interface {
	ListAnalyzers(ctx context.Context, params *accessanalyzer.ListAnalyzersInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error)
}

// AccessAnalyzerStatus represents the IAM Access Analyzer status.
type AccessAnalyzerStatus struct {
	Enabled       bool   `json:"enabled"`
	AnalyzerCount int    `json:"analyzer_count"`
	AnalyzerType  string `json:"analyzer_type,omitempty"`
	Region        string `json:"region"`
}

// ToEvidence converts an AccessAnalyzerStatus to Evidence.
func (s *AccessAnalyzerStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshalling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:access-analyzer:%s:%s:status", s.Region, accountID)
	ev := evidence.New("aws", "aws:accessanalyzer:status", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// AccessAnalyzerCollector collects Access Analyzer status.
type AccessAnalyzerCollector struct {
	client AccessAnalyzerClient
	region string
}

// NewAccessAnalyzerCollector creates a new Access Analyzer collector.
func NewAccessAnalyzerCollector(client AccessAnalyzerClient, region string) *AccessAnalyzerCollector {
	return &AccessAnalyzerCollector{client: client, region: region}
}

// CollectStatus retrieves Access Analyzer status.
func (c *AccessAnalyzerCollector) CollectStatus(ctx context.Context) (*AccessAnalyzerStatus, error) {
	status := &AccessAnalyzerStatus{Region: c.region}

	output, err := c.client.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	status.AnalyzerCount = len(output.Analyzers)
	status.Enabled = status.AnalyzerCount > 0

	if status.Enabled {
		status.AnalyzerType = string(output.Analyzers[0].Type)
	}

	return status, nil
}

// CollectEvidence collects Access Analyzer status as evidence.
func (c *AccessAnalyzerCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
