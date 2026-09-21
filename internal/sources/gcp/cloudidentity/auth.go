package cloudidentity

import (
	"context"
	"errors"
	"fmt"

	ciapi "google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// AuthConfig selects how the plugin authenticates to the Cloud Identity
// Policy API. It is deliberately the same shape as gcp.directory's —
// both read a Workspace/Cloud Identity account rather than a GCP project,
// so both face the same "ADC alone is not a Workspace admin" problem, and
// an operator who has configured one should not have to learn a second
// vocabulary for the other.
//
// Zero value: Application Default Credentials with the read-only policies
// scope. The ADC identity itself must be a Workspace SUPER ADMIN — the
// Policy API grants no narrower role.
//
// TargetServiceAccount: ADC (e.g. a Workload Identity Federation
// credential in CI) impersonates this service account via the IAM
// Credentials API, requesting the read-only scope. ADC needs
// roles/iam.serviceAccountTokenCreator on it.
//
// ImpersonateSubject (requires TargetServiceAccount): domain-wide
// delegation — the impersonated service account signs a JWT whose subject
// is this super admin's email. This is the path that actually works in
// practice, because a service account cannot be granted the super-admin
// role directly.
//
// THE SCOPE MUST BE ALLOW-LISTED VERBATIM. A super admin enters
// https://www.googleapis.com/auth/cloud-identity.policies.readonly in
// Security → API controls → Domain-wide delegation, character for
// character. A BROADER scope is not accepted in its place: allow-listing
// `.../cloud-identity` or `.../cloud-platform` and requesting the
// readonly scope fails with `unauthorized_client`, because the allow-list
// is matched by exact string and not by capability. That surprises
// everyone once; it is documented here, in docs/configuration.md §GCP,
// and in the guide, so it surprises nobody twice.
type AuthConfig struct {
	TargetServiceAccount string
	ImpersonateSubject   string
}

// errSubjectWithoutTarget is the config error for impersonate_subject set
// without target_service_account: domain-wide delegation needs a service
// account to sign the subject JWT, and ADC alone cannot supply one here.
var errSubjectWithoutTarget = errors.New(
	"gcp.cloud_identity: \"impersonate_subject\" requires \"target_service_account\" " +
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

// clientOptions builds the Policy API client options for cfg.
//
// This is also where the factory's credentials are RESOLVED rather than
// merely configured, which the source contract requires: a source the
// operator listed in `sources:` but has no credentials for is a config
// error (exit 3) before collection, not an empty collection afterwards.
// Both branches resolve eagerly — impersonate.CredentialsTokenSource
// looks up ADC as its base credential and errors when there is none, and
// on the plain-ADC branch ciapi.NewService does the same through
// google.FindDefaultCredentials. Neither is lazy the way the AWS and
// Azure chains are, which is why this plugin needs no extra probe.
func clientOptions(ctx context.Context, cfg AuthConfig) ([]option.ClientOption, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.TargetServiceAccount == "" {
		return []option.ClientOption{option.WithScopes(ciapi.CloudIdentityPoliciesReadonlyScope)}, nil
	}
	ts, err := newTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: cfg.TargetServiceAccount,
		Scopes:          []string{ciapi.CloudIdentityPoliciesReadonlyScope},
		Subject:         cfg.ImpersonateSubject,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp.cloud_identity: impersonate %s: %w", cfg.TargetServiceAccount, err)
	}
	return []option.ClientOption{option.WithTokenSource(ts)}, nil
}
