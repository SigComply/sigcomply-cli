package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// CognitoClient defines the interface for Cognito operations.
type CognitoClient interface {
	ListUserPools(ctx context.Context, params *cognitoidentityprovider.ListUserPoolsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error)
	DescribeUserPool(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error)
}

// CognitoUserPool represents a Cognito User Pool.
type CognitoUserPool struct {
	Name                 string `json:"name"`
	ARN                  string `json:"arn"`
	ID                   string `json:"id"`
	MFAConfiguration     string `json:"mfa_configuration"`
	MinPasswordLength    int    `json:"min_password_length"`
	RequireUppercase     bool   `json:"require_uppercase"`
	RequireLowercase     bool   `json:"require_lowercase"`
	RequireNumbers       bool   `json:"require_numbers"`
	RequireSymbols       bool   `json:"require_symbols"`
	AdvancedSecurityMode string `json:"advanced_security_mode"`
}

// ToEvidence converts a CognitoUserPool to Evidence.
func (p *CognitoUserPool) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(p) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:cognito:user-pool", p.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// CognitoCollector collects Cognito User Pool data.
type CognitoCollector struct {
	client CognitoClient
}

// NewCognitoCollector creates a new Cognito collector.
func NewCognitoCollector(client CognitoClient) *CognitoCollector {
	return &CognitoCollector{client: client}
}

// CollectUserPools retrieves all Cognito User Pools with their configuration.
func (c *CognitoCollector) CollectUserPools(ctx context.Context) ([]CognitoUserPool, error) {
	var pools []CognitoUserPool
	var nextToken *string

	for {
		output, err := c.client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{
			MaxResults: awssdk.Int32(60),
			NextToken:  nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Cognito user pools: %w", err)
		}

		for _, pool := range output.UserPools {
			up := CognitoUserPool{
				Name: awssdk.ToString(pool.Name),
				ID:   awssdk.ToString(pool.Id),
			}

			c.enrichUserPool(ctx, &up)
			pools = append(pools, up)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return pools, nil
}

// enrichUserPool fetches detailed user pool configuration.
func (c *CognitoCollector) enrichUserPool(ctx context.Context, pool *CognitoUserPool) {
	output, err := c.client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: awssdk.String(pool.ID),
	})
	if err != nil {
		return // Fail-safe
	}

	if output.UserPool != nil {
		pool.ARN = awssdk.ToString(output.UserPool.Arn)
		pool.MFAConfiguration = string(output.UserPool.MfaConfiguration)

		if output.UserPool.Policies != nil && output.UserPool.Policies.PasswordPolicy != nil {
			pp := output.UserPool.Policies.PasswordPolicy
			pool.MinPasswordLength = int(awssdk.ToInt32(pp.MinimumLength))
			pool.RequireUppercase = pp.RequireUppercase
			pool.RequireLowercase = pp.RequireLowercase
			pool.RequireNumbers = pp.RequireNumbers
			pool.RequireSymbols = pp.RequireSymbols
		}

		if output.UserPool.UserPoolAddOns != nil {
			pool.AdvancedSecurityMode = string(output.UserPool.UserPoolAddOns.AdvancedSecurityMode)
		}
	}
}

// CollectEvidence collects Cognito User Pools as evidence.
func (c *CognitoCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	pools, err := c.CollectUserPools(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(pools))
	for i := range pools {
		evidenceList = append(evidenceList, pools[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
