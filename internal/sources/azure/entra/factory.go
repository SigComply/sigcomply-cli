package entra

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

func init() {
	sources.RegisterFactory(SourceID, build, azcommon.ConfigKeys...)
}

// build constructs the azure.entra plugin from config. Entra is a Graph-plane
// source, so no subscription_id is required (ParseConfig false); the optional
// tenant_id tags record scope. Credentials come from the shared
// DefaultAzureCredential (see docs/configuration.md §Azure).
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	cfg, err := azcommon.ParseConfig(env.Config, false)
	if err != nil {
		return nil, err
	}
	cred, err := azcommon.NewCredential(ctx, azcommon.ScopeGraph)
	if err != nil {
		return nil, err
	}
	return NewFromGraph(ctx, cred, cfg)
}
