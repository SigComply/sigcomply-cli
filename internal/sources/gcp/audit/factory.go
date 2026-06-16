package audit

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

// build constructs the gcp.audit plugin from config. Audit posture is
// project-scoped: project_id is required. Credentials come from ADC with
// read-only scopes (see docs/configuration.md §GCP).
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	projectID := sources.StringOpt(env.Config, "project_id")
	if projectID == "" {
		return nil, fmt.Errorf("audit: project_id required")
	}
	return NewFromGCP(ctx, projectID)
}
