package securityservices

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	return NewFromAWS(ctx, sources.StringOpt(env.Config, "region"))
}
