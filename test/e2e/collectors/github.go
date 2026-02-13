//go:build e2e

package collectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sigcomply/sigcomply-cli/test/e2e/config"

	ghcollector "github.com/sigcomply/sigcomply-cli/internal/data_sources/apis/github"
)

func init() {
	Register("github", func() Collector { return &GitHubCollector{} })
}

// GitHubCollector adapts the internal GitHub collector for E2E tests.
type GitHubCollector struct {
	collector *ghcollector.Collector
}

// Provider returns "github".
func (c *GitHubCollector) Provider() string { return "github" }

// Init initializes the GitHub collector with credentials.
func (c *GitHubCollector) Init(ctx context.Context, t *testing.T, creds *config.ResolvedCredentials) error {
	t.Helper()

	token := creds.Values["token"]
	org := creds.Values["org"]

	c.collector = ghcollector.New()
	if token != "" {
		c.collector = c.collector.WithToken(token)
	}
	if org != "" {
		c.collector = c.collector.WithOrganization(org)
	}

	err := c.collector.Init(ctx)
	require.NoError(t, err, "GitHub collector Init failed")

	status := c.collector.Status(ctx)
	require.True(t, status.Connected, "GitHub collector not connected: %s", status.Error)
	t.Logf("Connected to GitHub as %s (org=%s)", status.Username, status.Organization)

	return nil
}

// Collect gathers evidence from GitHub, optionally filtered by services.
func (c *GitHubCollector) Collect(ctx context.Context, t *testing.T, services []string) (*CollectorResult, error) {
	t.Helper()

	result, err := c.collector.Collect(ctx)
	require.NoError(t, err, "GitHub Collect failed")
	require.NotNil(t, result, "Collection result is nil")

	// Convert internal errors to our type.
	// Note: GitHub uses "Resource" field, not "Service".
	collectorResult := &CollectorResult{}
	for _, e := range result.Errors {
		collectorResult.Errors = append(collectorResult.Errors, CollectorError{
			Service: e.Resource,
			Error:   e.Error,
		})
	}

	// Apply service filter
	collectorResult.Evidence = FilterByServices("github", services, result.Evidence)

	return collectorResult, nil
}
