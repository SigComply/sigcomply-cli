package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// AppSyncClient defines the interface for AppSync operations.
type AppSyncClient interface {
	ListGraphqlApis(ctx context.Context, params *appsync.ListGraphqlApisInput, optFns ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error)
}

// AppSyncAPI represents an AppSync GraphQL API.
type AppSyncAPI struct {
	Name           string `json:"name"`
	ARN            string `json:"arn"`
	LoggingEnabled bool   `json:"logging_enabled"`
}

// ToEvidence converts an AppSyncAPI to Evidence.
func (a *AppSyncAPI) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(a) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:appsync:api", a.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// AppSyncCollector collects AppSync GraphQL API data.
type AppSyncCollector struct {
	client AppSyncClient
}

// NewAppSyncCollector creates a new AppSync collector.
func NewAppSyncCollector(client AppSyncClient) *AppSyncCollector {
	return &AppSyncCollector{client: client}
}

// CollectAPIs retrieves all AppSync GraphQL APIs.
func (c *AppSyncCollector) CollectAPIs(ctx context.Context) ([]AppSyncAPI, error) {
	var apis []AppSyncAPI
	var nextToken *string

	for {
		output, err := c.client.ListGraphqlApis(ctx, &appsync.ListGraphqlApisInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list AppSync APIs: %w", err)
		}

		for i := range output.GraphqlApis {
			api := &output.GraphqlApis[i]
			a := AppSyncAPI{
				Name:           awssdk.ToString(api.Name),
				ARN:            awssdk.ToString(api.Arn),
				LoggingEnabled: api.LogConfig != nil,
			}
			apis = append(apis, a)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return apis, nil
}

// CollectEvidence collects AppSync APIs as evidence.
func (c *AppSyncCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	apis, err := c.CollectAPIs(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(apis))
	for i := range apis {
		evidenceList = append(evidenceList, apis[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
