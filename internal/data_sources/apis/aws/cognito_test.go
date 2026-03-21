package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockCognitoClient struct {
	ListUserPoolsFunc    func(ctx context.Context, params *cognitoidentityprovider.ListUserPoolsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error)
	DescribeUserPoolFunc func(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error)
}

func (m *MockCognitoClient) ListUserPools(ctx context.Context, params *cognitoidentityprovider.ListUserPoolsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error) {
	return m.ListUserPoolsFunc(ctx, params, optFns...)
}

func (m *MockCognitoClient) DescribeUserPool(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	if m.DescribeUserPoolFunc != nil {
		return m.DescribeUserPoolFunc(ctx, params, optFns...)
	}
	return &cognitoidentityprovider.DescribeUserPoolOutput{}, nil
}

func TestCognitoCollector_CollectUserPools(t *testing.T) {
	mock := &MockCognitoClient{
		ListUserPoolsFunc: func(ctx context.Context, params *cognitoidentityprovider.ListUserPoolsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error) {
			return &cognitoidentityprovider.ListUserPoolsOutput{
				UserPools: []cognitotypes.UserPoolDescriptionType{
					{Name: awssdk.String("secure-pool"), Id: awssdk.String("us-east-1_abc")},
					{Name: awssdk.String("weak-pool"), Id: awssdk.String("us-east-1_def")},
				},
			}, nil
		},
		DescribeUserPoolFunc: func(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
			if awssdk.ToString(params.UserPoolId) == "us-east-1_abc" {
				return &cognitoidentityprovider.DescribeUserPoolOutput{
					UserPool: &cognitotypes.UserPoolType{
						Arn:              awssdk.String("arn:aws:cognito-idp:us-east-1:123:userpool/us-east-1_abc"),
						MfaConfiguration: cognitotypes.UserPoolMfaTypeOn,
						Policies: &cognitotypes.UserPoolPolicyType{
							PasswordPolicy: &cognitotypes.PasswordPolicyType{
								MinimumLength:    awssdk.Int32(14),
								RequireUppercase: true,
								RequireLowercase: true,
								RequireNumbers:   true,
								RequireSymbols:   true,
							},
						},
						UserPoolAddOns: &cognitotypes.UserPoolAddOnsType{
							AdvancedSecurityMode: cognitotypes.AdvancedSecurityModeTypeEnforced,
						},
					},
				}, nil
			}
			return &cognitoidentityprovider.DescribeUserPoolOutput{
				UserPool: &cognitotypes.UserPoolType{
					Arn:              awssdk.String("arn:aws:cognito-idp:us-east-1:123:userpool/us-east-1_def"),
					MfaConfiguration: cognitotypes.UserPoolMfaTypeOff,
					Policies: &cognitotypes.UserPoolPolicyType{
						PasswordPolicy: &cognitotypes.PasswordPolicyType{
							MinimumLength:    awssdk.Int32(8),
							RequireUppercase: false,
							RequireLowercase: false,
							RequireNumbers:   false,
							RequireSymbols:   false,
						},
					},
				},
			}, nil
		},
	}

	collector := NewCognitoCollector(mock)
	pools, err := collector.CollectUserPools(context.Background())

	require.NoError(t, err)
	require.Len(t, pools, 2)

	assert.Equal(t, "secure-pool", pools[0].Name)
	assert.Equal(t, "ON", pools[0].MFAConfiguration)
	assert.Equal(t, 14, pools[0].MinPasswordLength)
	assert.True(t, pools[0].RequireUppercase)
	assert.Equal(t, "ENFORCED", pools[0].AdvancedSecurityMode)

	assert.Equal(t, "weak-pool", pools[1].Name)
	assert.Equal(t, "OFF", pools[1].MFAConfiguration)
	assert.Equal(t, 8, pools[1].MinPasswordLength)
}

func TestCognitoCollector_CollectEvidence(t *testing.T) {
	mock := &MockCognitoClient{
		ListUserPoolsFunc: func(ctx context.Context, params *cognitoidentityprovider.ListUserPoolsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error) {
			return &cognitoidentityprovider.ListUserPoolsOutput{
				UserPools: []cognitotypes.UserPoolDescriptionType{
					{Name: awssdk.String("pool"), Id: awssdk.String("us-east-1_abc")},
				},
			}, nil
		},
		DescribeUserPoolFunc: func(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
			return &cognitoidentityprovider.DescribeUserPoolOutput{
				UserPool: &cognitotypes.UserPoolType{
					Arn: awssdk.String("arn:aws:cognito-idp:us-east-1:123:userpool/us-east-1_abc"),
				},
			}, nil
		},
	}

	collector := NewCognitoCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:cognito:user-pool", ev[0].ResourceType)
}
