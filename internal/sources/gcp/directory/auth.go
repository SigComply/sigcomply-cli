package directory

import (
	"context"
	"errors"
	"fmt"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// AuthConfig selects how the plugin authenticates to the Admin SDK.
//
// Zero value: Application Default Credentials with the read-only user
// scope. The ADC identity itself must hold a Workspace admin role (for a
// service account: assigned an admin role with Users → Read).
//
// TargetServiceAccount: ADC (e.g. a Workload Identity Federation
// credential in CI) impersonates this service account via the IAM
// Credentials API, requesting the read-only scope. ADC needs
// roles/iam.serviceAccountTokenCreator on it.
//
// ImpersonateSubject (requires TargetServiceAccount): domain-wide
// delegation — the impersonated service account signs a JWT whose
// subject is this Workspace admin user. The service account's client ID
// must be allow-listed for the read-only scope in the Admin console.
type AuthConfig struct {
	TargetServiceAccount string
	ImpersonateSubject   string
}

// errSubjectWithoutTarget is the config error for impersonate_subject set
// without target_service_account: domain-wide delegation needs a service
// account to sign the subject JWT, and ADC alone cannot supply one here.
var errSubjectWithoutTarget = errors.New(
	"gcp.directory: \"impersonate_subject\" requires \"target_service_account\" " +
		"(domain-wide delegation signs as a service account)")

// Validate reports a configuration error for inconsistent auth settings.
func (a AuthConfig) Validate() error {
	if a.ImpersonateSubject != "" && a.TargetServiceAccount == "" {
		return errSubjectWithoutTarget
	}
	return nil
}

// newTokenSource is the seam over impersonate.CredentialsTokenSource so
// tests can capture the CredentialsConfig without calling Google.
var newTokenSource = impersonate.CredentialsTokenSource

// clientOptions builds the Admin SDK client options for cfg. Without
// impersonation it is exactly the pre-existing ADC + read-only scope
// path; with it, ADC is only the base credential for an impersonated
// token source scoped to the read-only directory scope.
func clientOptions(ctx context.Context, cfg AuthConfig) ([]option.ClientOption, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.TargetServiceAccount == "" {
		return []option.ClientOption{option.WithScopes(admin.AdminDirectoryUserReadonlyScope)}, nil
	}
	ts, err := newTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: cfg.TargetServiceAccount,
		Scopes:          []string{admin.AdminDirectoryUserReadonlyScope},
		Subject:         cfg.ImpersonateSubject,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp.directory: impersonate %s: %w", cfg.TargetServiceAccount, err)
	}
	return []option.ClientOption{option.WithTokenSource(ts)}, nil
}
