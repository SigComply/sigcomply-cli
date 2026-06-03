// Package passwordpolicy implements the aws.password_policy source
// plugin: reads the IAM account password policy and emits a single
// password_policy evidence record describing minimum length, expiry,
// reuse prevention, and the four character-class requirements.
//
// password_policy is a project/account-level singleton: this plugin
// always emits exactly one record. When no password policy is
// configured, AWS returns NoSuchEntityException; the plugin treats that
// as the weakest posture (all-false / zero) rather than an error, so the
// consuming policies correctly flag the missing policy.
//
// mfa_required is an IdP-level concept and is omitted (omitempty) for the
// AWS source — IAM models MFA per-user, not as a password-policy attribute.
package passwordpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "password_policy"

// SourceID is the registered ID for the aws.password_policy plugin instance.
const SourceID = "aws.password_policy"

// singletonID is the stable record ID for the account password policy.
// password_policy is a singleton; a stable ID avoids pulling in an STS
// dependency just to fetch the account number.
const singletonID = "account"

// API is the subset of the IAM client this plugin uses. Defining it as an
// interface lets tests inject a fake; the concrete *iam.Client satisfies it.
type API interface {
	GetAccountPasswordPolicy(ctx context.Context, params *awsiam.GetAccountPasswordPolicyInput, optFns ...func(*awsiam.Options)) (*awsiam.GetAccountPasswordPolicyOutput, error)
}

// Plugin is the in-process aws.password_policy source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
// Callers using the real AWS SDK should use NewFromAWS.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:    opts.API,
		region: opts.Region,
		now:    now,
	}
}

// NewFromAWS constructs a Plugin backed by the real AWS SDK using the
// default credential chain.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.password_policy: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsiam.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// passwordPolicyPayload is the cross-vendor password_policy shape.
type passwordPolicyPayload struct {
	ID                   string `json:"id"`
	Provider             string `json:"provider"`
	MinLength            int64  `json:"min_length"`
	MaxAgeDays           int64  `json:"max_age_days"`
	ReusePreventionCount int64  `json:"reuse_prevention_count"`
	RequiresUppercase    bool   `json:"requires_uppercase"`
	RequiresLowercase    bool   `json:"requires_lowercase"`
	RequiresNumbers      bool   `json:"requires_numbers"`
	RequiresSymbols      bool   `json:"requires_symbols"`
	// MFARequired is an IdP-only concept; omitted for AWS.
	MFARequired *bool `json:"mfa_required,omitempty"`
}

// Collect reads the account password policy and returns exactly one
// password_policy record. A missing policy (NoSuchEntityException) yields
// an all-false / zero record (weakest posture) rather than an error.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.password_policy: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}

	payload := passwordPolicyPayload{
		ID:       singletonID,
		Provider: "aws",
	}

	out, err := p.api.GetAccountPasswordPolicy(ctx, &awsiam.GetAccountPasswordPolicyInput{})
	switch {
	case err == nil && out != nil && out.PasswordPolicy != nil:
		pp := out.PasswordPolicy
		payload.MinLength = int64(deref32(pp.MinimumPasswordLength))
		payload.MaxAgeDays = int64(deref32(pp.MaxPasswordAge))
		payload.ReusePreventionCount = int64(deref32(pp.PasswordReusePrevention))
		payload.RequiresUppercase = pp.RequireUppercaseCharacters
		payload.RequiresLowercase = pp.RequireLowercaseCharacters
		payload.RequiresNumbers = pp.RequireNumbers
		payload.RequiresSymbols = pp.RequireSymbols
	case isNoSuchEntity(err):
		// No password policy configured. Leave payload at the zero/false
		// defaults so consuming policies flag the weakest posture.
	default:
		return nil, fmt.Errorf("aws.password_policy: get account password policy: %w", err)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("aws.password_policy: marshal payload: %w", err)
	}
	return []core.EvidenceRecord{{
		Type:        EvidenceTypeID,
		ID:          singletonID,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: p.now(),
	}}, nil
}

// isNoSuchEntity reports whether err is the IAM NoSuchEntityException that
// AWS returns when no account password policy is configured.
func isNoSuchEntity(err error) bool {
	if err == nil {
		return false
	}
	var nse *iamtypes.NoSuchEntityException
	return errors.As(err, &nse)
}

func deref32(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}

var _ core.SourcePlugin = (*Plugin)(nil)
