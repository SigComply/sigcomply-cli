package github

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
	org := sources.StringOpt(env.Config, "org")
	if org == "" {
		return nil, fmt.Errorf("github: \"org\" required")
	}
	token := sources.StringOpt(env.Config, "token")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("github: token required (set config token or GITHUB_TOKEN env)")
	}
	return NewFromToken(ctx, org, token)
}
