//go:build e2e

package collectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	awscollector "github.com/sigcomply/sigcomply-cli/internal/data_sources/apis/aws"
	"github.com/sigcomply/sigcomply-cli/test/e2e/config"
)

func init() {
	Register("aws", func() Collector { return &AWSCollector{} })
}

// AWSCollector adapts the internal AWS collector for E2E tests.
type AWSCollector struct {
	collector *awscollector.Collector
}

// Provider returns "aws".
func (c *AWSCollector) Provider() string { return "aws" }

// Init initializes the AWS collector with credentials.
func (c *AWSCollector) Init(ctx context.Context, t *testing.T, creds *config.ResolvedCredentials) error {
	t.Helper()

	region := creds.Values["region"]
	if region == "" {
		region = "us-east-1"
	}

	c.collector = awscollector.New().WithRegion(region)

	err := c.collector.Init(ctx)
	require.NoError(t, err, "AWS collector Init failed")

	status := c.collector.Status(ctx)
	require.True(t, status.Connected, "AWS collector not connected: %s", status.Error)
	t.Logf("Connected to AWS account %s in %s", status.AccountID, status.Region)

	return nil
}

// Collect gathers evidence from AWS, optionally filtered by services.
func (c *AWSCollector) Collect(ctx context.Context, t *testing.T, services []string) (*CollectorResult, error) {
	t.Helper()

	result, err := c.collector.Collect(ctx)
	require.NoError(t, err, "AWS Collect failed")
	require.NotNil(t, result, "Collection result is nil")

	// Convert internal errors to our type
	collectorResult := &CollectorResult{}
	for _, e := range result.Errors {
		collectorResult.Errors = append(collectorResult.Errors, CollectorError{
			Service: e.Service,
			Error:   e.Error,
		})
	}

	// Apply service filter
	collectorResult.Evidence = FilterByServices("aws", services, result.Evidence)

	return collectorResult, nil
}

