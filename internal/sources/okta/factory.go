package okta

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	orgURL := sources.StringOpt(env.Config, "org_url")
	if orgURL == "" {
		return nil, fmt.Errorf("okta: \"org_url\" required")
	}
	token, err := sources.ResolveToken(env.Config, SourceID, "api_token", "OKTA_API_TOKEN")
	if err != nil {
		return nil, err
	}
	return NewFromConfig(ctx, orgURL, token)
}
