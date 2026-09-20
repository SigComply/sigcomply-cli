package github

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build, "base_url", "org", "token", "token_env")
}

// build reads "org" and "token" (or GITHUB_TOKEN). Optional "base_url"
// targets a GitHub Enterprise Server instance instead of github.com.
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	org := sources.StringOpt(env.Config, "org")
	if org == "" {
		return nil, fmt.Errorf("github: \"org\" required")
	}
	token, err := sources.ResolveToken(env.Config, SourceID, "token", "GITHUB_TOKEN")
	if err != nil {
		return nil, err
	}
	baseURL := sources.StringOpt(env.Config, "base_url")
	return NewFromToken(ctx, org, token, baseURL)
}
