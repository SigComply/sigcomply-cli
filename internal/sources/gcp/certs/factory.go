package certs

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

// build constructs the gcp.certs plugin from config. Certificate Manager
// certificates are project-scoped: project_id is required. Credentials come
// from ADC with the cloud-platform scope; restrict access at the IAM layer
// with roles/certificatemanager.viewer (see docs/configuration.md §GCP).
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	projectID := sources.StringOpt(env.Config, "project_id")
	if projectID == "" {
		return nil, fmt.Errorf("certs: project_id required")
	}
	return NewFromGCP(ctx, projectID)
}
