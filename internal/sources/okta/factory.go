package okta

import (
	"context"
	"fmt"
	"os"

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
	token := sources.StringOpt(env.Config, "api_token")
	if token == "" {
		token = os.Getenv("OKTA_API_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("okta: api token required (set config api_token or OKTA_API_TOKEN env)")
	}
	return NewFromConfig(ctx, orgURL, token)
}
