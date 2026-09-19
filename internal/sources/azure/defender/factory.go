package defender

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

// build constructs the azure.defender plugin from config. Defender for Cloud is
// an ARM-plane source, so subscription_id is required (ParseConfig true).
// Credentials come from the shared DefaultAzureCredential (see
// docs/configuration.md §Azure).
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	cfg, err := azcommon.ParseConfig(env.Config, true)
	if err != nil {
		return nil, err
	}
	cred, err := azcommon.NewCredential(ctx, azcommon.ScopeARM)
	if err != nil {
		return nil, err
	}
	return NewFromAzure(cred, cfg)
}
