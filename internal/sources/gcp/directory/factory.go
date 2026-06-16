package directory

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

// build constructs the gcp.directory plugin from config. The directory
// is account/customer-scoped (not project-scoped): customer_id is
// optional and defaults to the "my_customer" alias resolving to the
// caller account's own organization. Credentials come from ADC carrying
// a Workspace admin context (see docs/configuration.md §GCP).
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	customer := sources.StringOpt(env.Config, "customer_id")
	return NewFromGCP(ctx, customer)
}
