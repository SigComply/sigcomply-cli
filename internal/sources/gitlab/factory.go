package gitlab

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

// build constructs the gitlab plugin from source config. Required:
// "group" (group ID or full path). Token comes from config "token" or the
// GITLAB_TOKEN env var. Optional "base_url" targets a self-managed
// instance (default gitlab.com). Scope: read_api.
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	group := sources.StringOpt(env.Config, "group")
	if group == "" {
		return nil, fmt.Errorf("gitlab: \"group\" required")
	}
	token, err := sources.ResolveToken(env.Config, SourceID, "token", "GITLAB_TOKEN")
	if err != nil {
		return nil, err
	}
	baseURL := sources.StringOpt(env.Config, "base_url")
	return NewFromToken(ctx, group, token, baseURL)
}
