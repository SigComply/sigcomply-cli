package github

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
	org := sources.StringOpt(env.Config, "org")
	if org == "" {
		return nil, fmt.Errorf("github: \"org\" required")
	}
	token, err := sources.ResolveToken(env.Config, SourceID, "token", "GITHUB_TOKEN")
	if err != nil {
		return nil, err
	}
	return NewFromToken(ctx, org, token)
}
