package gitlab

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

// build constructs the gitlab plugin from source config. Required:
// "group" (group ID or full path). Token comes from config "token" or the
// GITLAB_TOKEN env var. Optional "base_url" targets a self-managed
// instance (default gitlab.com). Scope: read_api.
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	group := sources.StringOpt(env.Config, "group")
	if group == "" {
		return nil, fmt.Errorf("gitlab: \"group\" required")
	}
	token := sources.StringOpt(env.Config, "token")
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("gitlab: token required (set config token or GITLAB_TOKEN env)")
	}
	baseURL := sources.StringOpt(env.Config, "base_url")
	return NewFromToken(ctx, group, token, baseURL)
}
