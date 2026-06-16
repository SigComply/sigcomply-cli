package network

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

// build constructs the gcp.network plugin from config. Networks are
// project-scoped: project_id is required. Credentials come from ADC with
// the read-only Compute scope (see docs/configuration.md §GCP).
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	projectID := sources.StringOpt(env.Config, "project_id")
	if projectID == "" {
		return nil, fmt.Errorf("network: project_id required")
	}
	return NewFromGCP(ctx, projectID)
}
