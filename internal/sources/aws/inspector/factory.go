package inspector

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awscfg"
)

func init() {
	sources.RegisterFactory(SourceID, build, awscfg.ConfigKeys...)
}

func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	return NewFromAWS(ctx, sources.StringOpt(env.Config, "region"), awscfg.FromEnv(env))
}
