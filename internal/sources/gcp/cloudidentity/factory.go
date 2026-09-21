package cloudidentity

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func init() {
	sources.RegisterFactory(SourceID, build, "target_service_account", "impersonate_subject")
}

// build constructs the gcp.cloud_identity plugin from config.
//
// There is deliberately no customer_id key, unlike gcp.directory. The
// Policy API scopes itself to the credential's own customer, and each
// Policy it returns names that customer, so the record's provenance stamp
// is read from the API rather than declared by the operator — one fewer
// thing that can be declared wrongly, and the only version of it that is
// evidence rather than assertion.
//
// Credentials come from ADC carrying a Workspace SUPER-ADMIN context,
// normally via service-account impersonation (target_service_account) plus
// domain-wide delegation (impersonate_subject, which requires
// target_service_account). The delegated scope must be allow-listed
// verbatim — see AuthConfig and docs/configuration.md §GCP.
func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
	auth := AuthConfig{
		TargetServiceAccount: sources.StringOpt(env.Config, "target_service_account"),
		ImpersonateSubject:   sources.StringOpt(env.Config, "impersonate_subject"),
	}
	if err := auth.Validate(); err != nil {
		return nil, err
	}
	return NewFromGCP(ctx, auth)
}
