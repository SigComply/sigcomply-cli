// Package awscfg builds the AWS SDK config for one configured source
// instance.
//
// It exists because "scan two AWS accounts" is not a region question.
// Every AWS plugin used to call LoadDefaultConfig itself, which resolves
// one ambient identity per process — so two configured instances, however
// they differed, authenticated as the same principal and returned the
// same account's resources under two different names. That is worse than
// not supporting multiple accounts at all: the vault ends up holding two
// sets of evidence that look independent and are not.
//
// An instance therefore declares how to reach its account:
//
//	sources:
//	  aws.iam:
//	    region: us-east-1
//	  "aws.iam[staging]":
//	    region: us-east-1
//	    role_arn: arn:aws:iam::210987654321:role/SigComplyAudit
//
// The base identity (whatever the runner already has) assumes that role,
// so the CI runner needs exactly one credential plus permission to assume
// each account's audit role — the standard cross-account pattern.
package awscfg

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// Options are the per-instance AWS settings read from `sources:`.
type Options struct {
	// Region is the AWS region to query.
	Region string
	// RoleARN, when set, is assumed from the ambient credentials. This
	// is the only way to reach a second account.
	RoleARN string
	// ExternalID is the optional confused-deputy guard required by some
	// cross-account trust policies.
	ExternalID string
	// SessionName labels the assumed session in CloudTrail. Defaults to
	// "sigcomply".
	SessionName string
}

// FromEnv reads the AWS options out of a source instance's config bag.
//
// Note there is deliberately no `profile` key. LoadDefaultConfig resolves
// AWS_ACCESS_KEY_ID/SECRET ahead of a shared-config profile, so on a CI
// runner with credentials exported — the normal case — a profile would be
// silently ignored and both instances would quietly scan the same
// account. A key that works locally and lies in CI is worse than no key.
func FromEnv(env sources.Env) Options {
	return Options{
		Region:      sources.StringOpt(env.Config, "region"),
		RoleARN:     strings.TrimSpace(sources.StringOpt(env.Config, "role_arn")),
		ExternalID:  strings.TrimSpace(sources.StringOpt(env.Config, "external_id")),
		SessionName: strings.TrimSpace(sources.StringOpt(env.Config, "role_session_name")),
	}
}

// cache memoizes one resolved config per distinct Options.
//
// Each of the ~23 AWS plugins builds its own client, so without this a
// single instance would issue 23 identical AssumeRole calls per run. The
// key is the full Options value, never a global — two instances with
// different roles must never share a resolved config, which is the whole
// point of the package.
var (
	mu     sync.Mutex
	cached = map[Options]aws.Config{}
)

// Load resolves the SDK config for one instance, assuming RoleARN when
// one is configured. The returned region is the effective one, which
// callers store on the plugin for record tagging.
func Load(ctx context.Context, opts Options) (aws.Config, string, error) {
	mu.Lock()
	defer mu.Unlock()
	if cfg, ok := cached[opts]; ok {
		return cfg, opts.Region, nil
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(opts.Region))
	if err != nil {
		return aws.Config{}, "", fmt.Errorf("load AWS config: %w", err)
	}

	if opts.RoleARN != "" {
		name := opts.SessionName
		if name == "" {
			name = "sigcomply"
		}
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), opts.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = name
			if opts.ExternalID != "" {
				o.ExternalID = aws.String(opts.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)

		// Resolve the credentials now rather than on the first API call.
		// A role that cannot be assumed must fail the run, not degrade it
		// to "this instance returned no records" — which the scope report
		// would otherwise render as an empty account rather than a
		// misconfiguration.
		if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
			return aws.Config{}, "", fmt.Errorf("assume role %s: %w", opts.RoleARN, err)
		}
	}

	cached[opts] = cfg
	return cfg, opts.Region, nil
}

// Reset clears the memoized configs. Test-only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	cached = map[Options]aws.Config{}
}
