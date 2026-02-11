//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	awscollector "github.com/sigcomply/sigcomply-cli/internal/data_sources/apis/aws"
)

// collectEvidence dispatches evidence collection to the appropriate provider.
// Add a case here when implementing a new collector (e.g. "gcp", "github").
func collectEvidence(t *testing.T, ctx context.Context, creds *ResolvedCredentials, scenario *Scenario) ([]evidence.Evidence, error) {
	t.Helper()

	switch creds.Provider {
	case "aws":
		return collectAWS(t, ctx, creds, scenario)
	default:
		return nil, fmt.Errorf("no collector implemented for provider %q", creds.Provider)
	}
}

// collectAWS initializes the AWS collector, verifies connectivity, and collects evidence.
func collectAWS(t *testing.T, ctx context.Context, creds *ResolvedCredentials, scenario *Scenario) ([]evidence.Evidence, error) {
	t.Helper()

	region := creds.Values["region"]
	if region == "" {
		region = "us-east-1"
	}

	collector := awscollector.New().WithRegion(region)

	err := collector.Init(ctx)
	require.NoError(t, err, "AWS collector Init failed")

	status := collector.Status(ctx)
	require.True(t, status.Connected, "AWS collector not connected: %s", status.Error)
	t.Logf("Connected to AWS account %s in %s", status.AccountID, status.Region)

	result, err := collector.Collect(ctx)
	require.NoError(t, err, "AWS Collect failed")
	require.NotNil(t, result, "Collection result is nil")

	if scenario.Assertions.CollectionErrorsExpected {
		assert.True(t, result.HasErrors(),
			"Expected collection errors (negative test) but got none")
		for _, e := range result.Errors {
			t.Logf("Expected collection error: service=%s error=%s", e.Service, e.Error)
		}
	} else if result.HasErrors() {
		for _, e := range result.Errors {
			t.Logf("Collection warning: service=%s error=%s", e.Service, e.Error)
		}
	}

	evidenceList := result.Evidence

	// Always require evidence for positive scenarios
	if !scenario.Assertions.CollectionErrorsExpected {
		require.NotEmpty(t, evidenceList, "No evidence collected")
	}

	t.Logf("Collected %d evidence items", len(evidenceList))

	return evidenceList, nil
}
