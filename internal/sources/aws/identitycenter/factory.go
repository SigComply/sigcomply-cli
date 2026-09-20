package identitycenter

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awscfg"
)

func init() {
	sources.RegisterFactory(SourceID, build, append(awscfg.ConfigKeys, "identity_store_id")...)
}

// build resolves credentials eagerly (awscfg.Load, inside NewFromAWS) so a
// source listed in `sources:` with no usable credentials fails the run as a
// config error. `identity_store_id` is optional: left empty, Collect discovers
// it from the single visible Identity Center instance — deliberately NOT here,
// so the factory makes no API call and the plugin constructs on a bare runner.
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	return NewFromAWS(ctx,
		sources.StringOpt(env.Config, "region"),
		sources.StringOpt(env.Config, "identity_store_id"),
		awscfg.FromEnv(env),
	)
}
