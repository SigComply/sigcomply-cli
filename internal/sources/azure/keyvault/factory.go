package keyvault

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

func init() {
	sources.RegisterFactory(SourceID, build, azcommon.ConfigKeys...)
}

// build constructs the azure.keyvault plugin from config. Key Vault is an
// ARM-plane source, so subscription_id is required (ParseConfig true).
// Credentials come from the shared DefaultAzureCredential (see
// docs/configuration.md §Azure). All reads stay on the management plane —
// Reader RBAC, no Key Vault data-plane access policies.
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
