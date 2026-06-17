package monitor

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

// build constructs the azure.monitor plugin from config. Monitor is an ARM-plane
// source, so subscription_id is required (ParseConfig true). Credentials come from
// the shared DefaultAzureCredential (see docs/configuration.md §Azure).
func build(_ context.Context, env sources.Env) (core.SourcePlugin, error) {
	cfg, err := azcommon.ParseConfig(env.Config, true)
	if err != nil {
		return nil, err
	}
	cred, err := azcommon.NewCredential()
	if err != nil {
		return nil, err
	}
	return NewFromAzure(cred, cfg)
}
