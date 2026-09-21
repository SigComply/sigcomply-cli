// Package passwordpolicy implements the aws.password_policy source
// plugin: reads the IAM account password policy and emits a single
// password_policy.v2 evidence record describing minimum length, expiry,
// reuse prevention, and the four character-class requirements.
//
// An AWS account has exactly one password policy, so this plugin always
// emits exactly one record — that is a property of IAM, not of the
// evidence type: an IdP source may emit several (Okta assigns password
// policies per group). When no password policy is
// configured, AWS returns NoSuchEntityException; the plugin treats that
// as the weakest posture (complexity_model "none", zero length and age)
// rather than an error, so the consuming policies correctly flag the
// missing policy. Those zeros are observed, not assumed: AWS answered
// "there is no policy", which is exactly the statement "no minimum is
// imposed" — the case v2's absent-vs-zero rule is drawn around.
//
// # v2 only, never both versions
//
// The six consuming policies accept password_policy AND
// password_policy.v2, so a project-local plugin still emitting v1 keeps
// binding. This plugin emits only v2, and emitting both would be a bug
// rather than a kindness: a binding's Collect is called once with every
// accepted type it can satisfy, and every record it returns lands in the
// same slot (see internal/collector). Two records describing one IAM
// policy would double resources_evaluated on the wire, write two signed
// envelopes for one fact, and give an auditor two documents to reconcile.
// Emitting v1 only would be the other failure: the slot would still bind,
// but the reframed complexity clause cannot read a v1 record's model, and
// a v2-only slot would not bind at all — the sibling-version CoverageGap
// the planner warns about.
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

	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awscfg"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "password_policy.v2"

// SourceID is the registered ID for the aws.password_policy plugin instance.
const SourceID = "aws.password_policy"

// singletonID is the stable record ID for the account password policy.
// password_policy is a singleton; a stable ID avoids pulling in an STS
// dependency just to fetch the account number.
const singletonID = "account"

// Canonical password_policy.v2 vocabulary this plugin emits. scopeAccount
// because an IAM password policy governs every user in the account;
// complexityPerClass because IAM states its requirement as four
// character-class flags; complexityNone for an account with no policy at
// all, which is an observed absence of any strength requirement rather
// than an unread one.
const (
	scopeAccount       = "account"
	complexityPerClass = "per_class"
	complexityNone     = "none"
)

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
// instance's resolved credentials (see awscfg).
// The variadic opts carry per-instance credential settings (see
// internal/sources/aws/awscfg). Omitting them keeps the previous
// behavior: the ambient credential chain, scoped to region.
func NewFromAWS(ctx context.Context, region string, opts ...awscfg.Options) (*Plugin, error) {
	o := awscfg.Options{Region: region}
	if len(opts) > 0 {
		o = opts[0]
		if o.Region == "" {
			o.Region = region
		}
	}
	cfg, region, err := awscfg.Load(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("aws.password_policy: %w", err)
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

// passwordPolicyPayload is the cross-vendor password_policy.v2 shape.
//
// The four character-class booleans are pointers so that the
// no-policy-configured record can omit them: complexity_model "none" says
// no strength requirement is in force, and repeating that as four falses
// under a per-class model nobody declared would invite the reading that
// AWS answered per-class and said no. Every other field is a plain value
// because IAM either reports it or reports that the policy does not exist
// — in both cases the value is observed.
type passwordPolicyPayload struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	// Scope and Precedence are constants for IAM and say so honestly: an
	// account has exactly one password policy, it governs every IAM user
	// in the account, and with no siblings to compete with it ranks first.
	Scope                string `json:"scope"`
	Precedence           int    `json:"precedence"`
	MinLength            int64  `json:"min_length"`
	MaxAgeDays           int64  `json:"max_age_days"`
	ReusePrevented       bool   `json:"reuse_prevented"`
	ReusePreventionCount int64  `json:"reuse_prevention_count"`
	ComplexityModel      string `json:"complexity_model"`
	RequiresUppercase    *bool  `json:"requires_uppercase,omitempty"`
	RequiresLowercase    *bool  `json:"requires_lowercase,omitempty"`
	RequiresNumbers      *bool  `json:"requires_numbers,omitempty"`
	RequiresSymbols      *bool  `json:"requires_symbols,omitempty"`
	// MFARequired is an IdP-only concept; omitted for AWS.
	MFARequired *bool `json:"mfa_required,omitempty"`
}

// Collect reads the account password policy and returns exactly one
// password_policy.v2 record. A missing policy (NoSuchEntityException)
// yields the weakest posture — no minimum, no expiry, no history, and
// complexity_model "none" — rather than an error. Those zeros are the
// one place in this plugin where a zero is written without a value
// having been read, and they are still observed rather than assumed:
// AWS answered "there is no policy", which is the same statement as "no
// minimum is imposed". Contrast the fields v2 lets a source omit, where
// nothing was reported at all.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.password_policy: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}

	payload := passwordPolicyPayload{
		ID:         singletonID,
		Provider:   "aws",
		Scope:      scopeAccount,
		Precedence: 1,
		// No policy configured is the default branch below: an account
		// that imposes no strength requirement at all, which is "none"
		// rather than a per-class answer of four noes.
		ComplexityModel: complexityNone,
	}

	out, err := p.api.GetAccountPasswordPolicy(ctx, &awsiam.GetAccountPasswordPolicyInput{})
	switch {
	case err == nil && out != nil && out.PasswordPolicy != nil:
		pp := out.PasswordPolicy
		payload.MinLength = int64(deref32(pp.MinimumPasswordLength))
		payload.MaxAgeDays = int64(deref32(pp.MaxPasswordAge))
		payload.ReusePreventionCount = int64(deref32(pp.PasswordReusePrevention))
		// IAM states the history depth, so the canonical boolean is
		// derived from it rather than guessed: a depth of zero is AWS
		// reporting that no history is kept.
		payload.ReusePrevented = payload.ReusePreventionCount >= 1
		payload.ComplexityModel = complexityPerClass
		payload.RequiresUppercase = &pp.RequireUppercaseCharacters
		payload.RequiresLowercase = &pp.RequireLowercaseCharacters
		payload.RequiresNumbers = &pp.RequireNumbers
		payload.RequiresSymbols = &pp.RequireSymbols
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
