package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// AccountPasswordPolicy represents the IAM account password policy.
type AccountPasswordPolicy struct {
	MaxPasswordAge             int  `json:"max_password_age"`
	MinimumPasswordLength      int  `json:"minimum_password_length"`
	RequireSymbols             bool `json:"require_symbols"`
	RequireNumbers             bool `json:"require_numbers"`
	RequireUppercaseCharacters bool `json:"require_uppercase_characters"`
	RequireLowercaseCharacters bool `json:"require_lowercase_characters"`
	AllowUsersToChangePassword bool `json:"allow_users_to_change_password"`
	PasswordReusePrevention    int  `json:"password_reuse_prevention"`
	HardExpiry                 bool `json:"hard_expiry"`
	HasPolicy                  bool `json:"has_policy"`
}

// ToEvidence converts an AccountPasswordPolicy to Evidence.
func (p *AccountPasswordPolicy) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(p) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("arn:aws:iam::%s:account-password-policy", accountID)
	ev := evidence.New("aws", "aws:iam:password-policy", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// AccountClient defines the interface for account-level IAM operations.
type AccountClient interface {
	GetAccountPasswordPolicy(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GetAccountSummary(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
}

// AccountCollector collects account-level IAM data.
type AccountCollector struct {
	client AccountClient
}

// NewAccountCollector creates a new account collector.
func NewAccountCollector(client AccountClient) *AccountCollector {
	return &AccountCollector{client: client}
}

// CollectPasswordPolicy retrieves the IAM account password policy.
func (c *AccountCollector) CollectPasswordPolicy(ctx context.Context) (*AccountPasswordPolicy, error) {
	output, err := c.client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		// No password policy set — this is a valid state, not an error
		return &AccountPasswordPolicy{HasPolicy: false}, nil //nolint:nilerr // no password policy is a valid state
	}

	pp := output.PasswordPolicy
	return &AccountPasswordPolicy{
		HasPolicy:                  true,
		MaxPasswordAge:             int(awssdk.ToInt32(pp.MaxPasswordAge)),
		MinimumPasswordLength:      int(awssdk.ToInt32(pp.MinimumPasswordLength)),
		RequireSymbols:             pp.RequireSymbols,
		RequireNumbers:             pp.RequireNumbers,
		RequireUppercaseCharacters: pp.RequireUppercaseCharacters,
		RequireLowercaseCharacters: pp.RequireLowercaseCharacters,
		AllowUsersToChangePassword: pp.AllowUsersToChangePassword,
		PasswordReusePrevention:    int(awssdk.ToInt32(pp.PasswordReusePrevention)),
		HardExpiry:                 awssdk.ToBool(pp.HardExpiry),
	}, nil
}

// RootAccountSummary represents root account security settings.
type RootAccountSummary struct {
	AccountMFAEnabled        bool `json:"account_mfa_enabled"`
	AccountAccessKeysPresent int  `json:"account_access_keys_present"`
}

// ToEvidence converts a RootAccountSummary to Evidence.
func (r *RootAccountSummary) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(r) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("arn:aws:iam::%s:root", accountID)
	ev := evidence.New("aws", "aws:iam:root-account", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// CollectRootAccountSummary retrieves root account security settings.
func (c *AccountCollector) CollectRootAccountSummary(ctx context.Context) (*RootAccountSummary, error) {
	output, err := c.client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get account summary: %w", err)
	}

	summary := &RootAccountSummary{}
	if v, ok := output.SummaryMap["AccountMFAEnabled"]; ok {
		summary.AccountMFAEnabled = v == 1
	}
	if v, ok := output.SummaryMap["AccountAccessKeysPresent"]; ok {
		summary.AccountAccessKeysPresent = int(v)
	}

	return summary, nil
}

// CollectEvidence collects account-level evidence.
func (c *AccountCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	// Password policy
	pp, err := c.CollectPasswordPolicy(ctx)
	if err != nil {
		return nil, err
	}
	evidenceList = append(evidenceList, pp.ToEvidence(accountID))

	// Root account summary
	root, err := c.CollectRootAccountSummary(ctx)
	if err != nil {
		// Fail-safe: continue without root account info
		_ = err
	} else {
		evidenceList = append(evidenceList, root.ToEvidence(accountID))
	}

	return evidenceList, nil
}
