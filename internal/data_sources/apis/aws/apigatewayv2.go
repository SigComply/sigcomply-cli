package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// APIGatewayV2Client defines the interface for API Gateway V2 (HTTP/WebSocket) operations.
type APIGatewayV2Client interface {
	GetApis(ctx context.Context, params *apigatewayv2.GetApisInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error)
	GetStages(ctx context.Context, params *apigatewayv2.GetStagesInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error)
}

// APIGatewayV2API represents an API Gateway V2 HTTP or WebSocket API.
type APIGatewayV2API struct {
	Name                 string `json:"name"`
	ARN                  string `json:"arn"`
	AccessLoggingEnabled bool   `json:"access_logging_enabled"`
}

// ToEvidence converts an APIGatewayV2API to Evidence.
func (a *APIGatewayV2API) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(a) //nolint:errcheck // marshalling a known struct type will not fail
	ev := evidence.New("aws", "aws:apigateway:v2-api", a.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// APIGatewayV2Collector collects API Gateway V2 data.
type APIGatewayV2Collector struct {
	client APIGatewayV2Client
}

// NewAPIGatewayV2Collector creates a new API Gateway V2 collector.
func NewAPIGatewayV2Collector(client APIGatewayV2Client) *APIGatewayV2Collector {
	return &APIGatewayV2Collector{client: client}
}

// CollectAPIs retrieves all API Gateway V2 APIs with access logging status.
func (c *APIGatewayV2Collector) CollectAPIs(ctx context.Context) ([]APIGatewayV2API, error) {
	var apis []APIGatewayV2API
	var nextToken *string

	for {
		output, err := c.client.GetApis(ctx, &apigatewayv2.GetApisInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list API Gateway V2 APIs: %w", err)
		}

		for i := range output.Items {
			item := &output.Items[i]
			apiID := awssdk.ToString(item.ApiId)
			api := APIGatewayV2API{
				Name: awssdk.ToString(item.Name),
				ARN:  fmt.Sprintf("arn:aws:apigateway::%s:/apis/%s", "", apiID),
			}

			// Check stages for access logging
			c.enrichAccessLogging(ctx, apiID, &api)
			apis = append(apis, api)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return apis, nil
}

// enrichAccessLogging checks if any stage has access logging configured.
func (c *APIGatewayV2Collector) enrichAccessLogging(ctx context.Context, apiID string, api *APIGatewayV2API) {
	output, err := c.client.GetStages(ctx, &apigatewayv2.GetStagesInput{
		ApiId: awssdk.String(apiID),
	})
	if err != nil {
		return // Fail-safe
	}

	for _, stage := range output.Items {
		if stage.AccessLogSettings != nil && awssdk.ToString(stage.AccessLogSettings.DestinationArn) != "" {
			api.AccessLoggingEnabled = true
			return
		}
	}
}

// CollectEvidence collects API Gateway V2 APIs as evidence.
func (c *APIGatewayV2Collector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
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
