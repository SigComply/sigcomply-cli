package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockAccountClient implements AccountClient for testing.
type MockAccountClient struct {
	GetAccountPasswordPolicyFunc func(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GetAccountSummaryFunc        func(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	ListAccessKeysFunc           func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
}

func (m *MockAccountClient) GetAccountPasswordPolicy(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	return m.GetAccountPasswordPolicyFunc(ctx, params, optFns...)
}

func (m *MockAccountClient) GetAccountSummary(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return m.GetAccountSummaryFunc(ctx, params, optFns...)
}

func (m *MockAccountClient) ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return m.ListAccessKeysFunc(ctx, params, optFns...)
}

func TestAccountCollector_CollectPasswordPolicy(t *testing.T) {
	tests := []struct {
		name       string
		mockOutput *iam.GetAccountPasswordPolicyOutput
		mockErr    error
		wantPolicy *AccountPasswordPolicy
	}{
		{
			name: "strong password policy",
			mockOutput: &iam.GetAccountPasswordPolicyOutput{
				PasswordPolicy: &iamtypes.PasswordPolicy{
					MaxPasswordAge:             awssdk.Int32(90),
					MinimumPasswordLength:      awssdk.Int32(14),
					RequireSymbols:             true,
					RequireNumbers:             true,
					RequireUppercaseCharacters: true,
					RequireLowercaseCharacters: true,
					AllowUsersToChangePassword: true,
					PasswordReusePrevention:    awssdk.Int32(24),
					HardExpiry:                 awssdk.Bool(false),
				},
			},
			wantPolicy: &AccountPasswordPolicy{
				HasPolicy:                  true,
				MaxPasswordAge:             90,
				MinimumPasswordLength:      14,
				RequireSymbols:             true,
				RequireNumbers:             true,
				RequireUppercaseCharacters: true,
				RequireLowercaseCharacters: true,
				AllowUsersToChangePassword: true,
				PasswordReusePrevention:    24,
				HardExpiry:                 false,
			},
		},
		{
			name:    "no password policy set",
			mockErr: errors.New("NoSuchEntity: no policy"),
			wantPolicy: &AccountPasswordPolicy{
				HasPolicy: false,
			},
		},
		{
			name: "weak password policy",
			mockOutput: &iam.GetAccountPasswordPolicyOutput{
				PasswordPolicy: &iamtypes.PasswordPolicy{
					MinimumPasswordLength:      awssdk.Int32(6),
					RequireSymbols:             false,
					RequireNumbers:             false,
					RequireUppercaseCharacters: false,
					RequireLowercaseCharacters: false,
				},
			},
			wantPolicy: &AccountPasswordPolicy{
				HasPolicy:             true,
				MinimumPasswordLength: 6,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockAccountClient{
				GetAccountPasswordPolicyFunc: func(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return tt.mockOutput, nil
				},
			}

			collector := NewAccountCollector(mock)
			policy, err := collector.CollectPasswordPolicy(context.Background())

			require.NoError(t, err, "CollectPasswordPolicy should not error even when API fails")
			assert.Equal(t, tt.wantPolicy.HasPolicy, policy.HasPolicy)
			assert.Equal(t, tt.wantPolicy.MinimumPasswordLength, policy.MinimumPasswordLength)
			assert.Equal(t, tt.wantPolicy.RequireSymbols, policy.RequireSymbols)
			assert.Equal(t, tt.wantPolicy.MaxPasswordAge, policy.MaxPasswordAge)
		})
	}
}

func TestAccountCollector_CollectRootAccountSummary(t *testing.T) {
	tests := []struct {
		name       string
		summaryMap map[string]int32
		mockErr    error
		wantMFA    bool
		wantKeys   int
		wantError  bool
	}{
		{
			name: "root with MFA and no access keys",
			summaryMap: map[string]int32{
				"AccountMFAEnabled":        1,
				"AccountAccessKeysPresent": 0,
			},
			wantMFA:  true,
			wantKeys: 0,
		},
		{
			name: "root without MFA and with access keys",
			summaryMap: map[string]int32{
				"AccountMFAEnabled":        0,
				"AccountAccessKeysPresent": 2,
			},
			wantMFA:  false,
			wantKeys: 2,
		},
		{
			name:      "API error",
			mockErr:   errors.New("access denied"),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockAccountClient{
				GetAccountSummaryFunc: func(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return &iam.GetAccountSummaryOutput{SummaryMap: tt.summaryMap}, nil
				},
			}

			collector := NewAccountCollector(mock)
			summary, err := collector.CollectRootAccountSummary(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantMFA, summary.AccountMFAEnabled)
			assert.Equal(t, tt.wantKeys, summary.AccountAccessKeysPresent)
		})
	}
}

func TestAccountCollector_CollectEvidence(t *testing.T) {
	mock := &MockAccountClient{
		GetAccountPasswordPolicyFunc: func(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
			return &iam.GetAccountPasswordPolicyOutput{
				PasswordPolicy: &iamtypes.PasswordPolicy{
					MinimumPasswordLength: awssdk.Int32(14),
				},
			}, nil
		},
		GetAccountSummaryFunc: func(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
			return &iam.GetAccountSummaryOutput{
				SummaryMap: map[string]int32{
					"AccountMFAEnabled":        1,
					"AccountAccessKeysPresent": 0,
				},
			}, nil
		},
	}

	collector := NewAccountCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.Len(t, ev, 2, "should have password policy + root account evidence")
	assert.Equal(t, "aws:iam:password-policy", ev[0].ResourceType)
	assert.Equal(t, "aws:iam:root-account", ev[1].ResourceType)
}

func TestAccountCollector_CollectEvidence_RootSummaryFailSafe(t *testing.T) {
	mock := &MockAccountClient{
		GetAccountPasswordPolicyFunc: func(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
			return &iam.GetAccountPasswordPolicyOutput{
				PasswordPolicy: &iamtypes.PasswordPolicy{
					MinimumPasswordLength: awssdk.Int32(8),
				},
			}, nil
		},
		GetAccountSummaryFunc: func(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewAccountCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err, "should not fail when root summary fails (fail-safe)")
	assert.Len(t, ev, 1, "should only have password policy evidence")
}

func TestAccountPasswordPolicy_ToEvidence(t *testing.T) {
	policy := &AccountPasswordPolicy{
		HasPolicy:             true,
		MinimumPasswordLength: 14,
		RequireSymbols:        true,
	}

	ev := policy.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:iam:password-policy", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "123456789012")
	assert.NotEmpty(t, ev.Hash)
}

func TestRootAccountSummary_ToEvidence(t *testing.T) {
	summary := &RootAccountSummary{
		AccountMFAEnabled:        true,
		AccountAccessKeysPresent: 0,
	}

	ev := summary.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:iam:root-account", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "root")
	assert.NotEmpty(t, ev.Hash)
}

// --- Negative Tests ---

func TestAccountCollector_CollectRootAccountSummary_EmptySummaryMap(t *testing.T) {
	mock := &MockAccountClient{
		GetAccountSummaryFunc: func(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
			return &iam.GetAccountSummaryOutput{SummaryMap: map[string]int32{}}, nil
		},
	}

	collector := NewAccountCollector(mock)
	summary, err := collector.CollectRootAccountSummary(context.Background())

	require.NoError(t, err)
	assert.False(t, summary.AccountMFAEnabled, "should default to false when key missing")
	assert.Equal(t, 0, summary.AccountAccessKeysPresent, "should default to 0 when key missing")
}

func TestAccountCollector_CollectRootAccountSummary_NilSummaryMap(t *testing.T) {
	mock := &MockAccountClient{
		GetAccountSummaryFunc: func(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
			return &iam.GetAccountSummaryOutput{SummaryMap: nil}, nil
		},
	}

	collector := NewAccountCollector(mock)
	summary, err := collector.CollectRootAccountSummary(context.Background())

	require.NoError(t, err)
	assert.False(t, summary.AccountMFAEnabled)
	assert.Equal(t, 0, summary.AccountAccessKeysPresent)
}

func TestAccountCollector_CollectEvidence_BothSubCollectorsFail(t *testing.T) {
	// When password policy fails, CollectEvidence returns the no-policy default (HasPolicy=false)
	// When root summary fails, it's skipped (fail-safe)
	mock := &MockAccountClient{
		GetAccountPasswordPolicyFunc: func(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
			return nil, errors.New("service unavailable")
		},
		GetAccountSummaryFunc: func(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
			return nil, errors.New("throttling")
		},
	}

	collector := NewAccountCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	// Password policy error returns HasPolicy=false (not an error), root summary is fail-safe
	require.NoError(t, err)
	assert.Len(t, ev, 1, "should have password policy evidence only (root summary skipped)")
	assert.Equal(t, "aws:iam:password-policy", ev[0].ResourceType)
}

func TestAccountCollector_CollectPasswordPolicy_NilFields(t *testing.T) {
	// Password policy with all nil optional Int32 fields
	mock := &MockAccountClient{
		GetAccountPasswordPolicyFunc: func(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
			return &iam.GetAccountPasswordPolicyOutput{
				PasswordPolicy: &iamtypes.PasswordPolicy{
					// All pointer fields are nil
					MaxPasswordAge:          nil,
					MinimumPasswordLength:   nil,
					PasswordReusePrevention: nil,
					HardExpiry:              nil,
				},
			}, nil
		},
	}

	collector := NewAccountCollector(mock)
	policy, err := collector.CollectPasswordPolicy(context.Background())

	require.NoError(t, err)
	assert.True(t, policy.HasPolicy)
	assert.Equal(t, 0, policy.MaxPasswordAge, "nil Int32 should become 0")
	assert.Equal(t, 0, policy.MinimumPasswordLength, "nil Int32 should become 0")
	assert.Equal(t, 0, policy.PasswordReusePrevention, "nil Int32 should become 0")
	assert.False(t, policy.HardExpiry, "nil Bool should become false")
}
