package scc

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

// build constructs the gcp.scc plugin from config. Security Command Center
// is organization-scoped, so organization_id is required (not the
// project_id the other gcp.* plugins use). Credentials come from ADC; the
// service account needs org-level securitycenter.findingsViewer +
// settingsViewer (see docs/configuration.md §GCP).
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	orgID := sources.StringOpt(env.Config, "organization_id")
	if orgID == "" {
		return nil, fmt.Errorf("scc: organization_id required")
	}
	return NewFromGCP(ctx, orgID)
}
