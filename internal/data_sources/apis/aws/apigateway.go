package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// APIGatewayClient defines the interface for API Gateway operations.
type APIGatewayClient interface {
	GetRestApis(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error)
	GetStages(ctx context.Context, params *apigateway.GetStagesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error)
	GetAuthorizers(ctx context.Context, params *apigateway.GetAuthorizersInput, optFns ...func(*apigateway.Options)) (*apigateway.GetAuthorizersOutput, error)
}

// APIGatewayStage represents an API Gateway stage.
type APIGatewayStage struct {
	StageName              string `json:"stage_name"`
	LoggingEnabled         bool   `json:"logging_enabled"`
	AccessLogEnabled       bool   `json:"access_log_enabled"`
	CacheEncryptionEnabled bool   `json:"cache_encryption_enabled"`
	ThrottlingEnabled      bool   `json:"throttling_enabled"`
}

// APIGatewayAPI represents an API Gateway REST API with its stages.
type APIGatewayAPI struct {
	APIID         string            `json:"api_id"`
	Name          string            `json:"name"`
	WAFEnabled    bool              `json:"waf_enabled"`
	HasAuthorizer bool              `json:"has_authorizer"`
	Stages        []APIGatewayStage `json:"stages"`
}

// ToEvidence converts an APIGatewayAPI to Evidence.
func (a *APIGatewayAPI) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(a) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:apigateway::%s::/restapis/%s", accountID, a.APIID)
	ev := evidence.New("aws", "aws:apigateway:rest_api", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// APIGatewayCollector collects API Gateway data.
type APIGatewayCollector struct {
	client APIGatewayClient
}

// NewAPIGatewayCollector creates a new API Gateway collector.
func NewAPIGatewayCollector(client APIGatewayClient) *APIGatewayCollector {
	return &APIGatewayCollector{client: client}
}

// CollectAPIs retrieves all REST APIs with their stages.
func (c *APIGatewayCollector) CollectAPIs(ctx context.Context) ([]APIGatewayAPI, error) {
	var apis []APIGatewayAPI
	var position *string

	for {
		output, err := c.client.GetRestApis(ctx, &apigateway.GetRestApisInput{
			Position: position,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get REST APIs: %w", err)
		}

		for _, item := range output.Items {
			api := APIGatewayAPI{
				APIID: awssdk.ToString(item.Id),
				Name:  awssdk.ToString(item.Name),
			}

			c.enrichStages(ctx, &api)
			c.enrichAuthorizers(ctx, &api)
			apis = append(apis, api)
		}

		if output.Position == nil {
			break
		}
		position = output.Position
	}

	return apis, nil
}

// enrichStages retrieves and adds stage information to an API.
func (c *APIGatewayCollector) enrichStages(ctx context.Context, api *APIGatewayAPI) {
	output, err := c.client.GetStages(ctx, &apigateway.GetStagesInput{
		RestApiId: awssdk.String(api.APIID),
	})
	if err != nil {
		return // Fail-safe
	}

	for _, stage := range output.Item {
		s := APIGatewayStage{
			StageName: awssdk.ToString(stage.StageName),
		}

		// Check execution logging via method settings
		if settings, ok := stage.MethodSettings["*/*"]; ok {
			s.LoggingEnabled = awssdk.ToString(settings.LoggingLevel) != "OFF" && awssdk.ToString(settings.LoggingLevel) != ""
			s.CacheEncryptionEnabled = settings.CacheDataEncrypted
			s.ThrottlingEnabled = settings.ThrottlingRateLimit > 0 || settings.ThrottlingBurstLimit > 0
		}

		// Check access logging
		if stage.AccessLogSettings != nil && stage.AccessLogSettings.DestinationArn != nil {
			s.AccessLogEnabled = true
		}

		// Check WAF association
		if awssdk.ToString(stage.WebAclArn) != "" {
			api.WAFEnabled = true
		}

		api.Stages = append(api.Stages, s)
	}
}

// enrichAuthorizers checks if the API has any authorizers configured.
func (c *APIGatewayCollector) enrichAuthorizers(ctx context.Context, api *APIGatewayAPI) {
	output, err := c.client.GetAuthorizers(ctx, &apigateway.GetAuthorizersInput{
		RestApiId: awssdk.String(api.APIID),
	})
	if err != nil {
		return // Fail-safe
	}
	api.HasAuthorizer = len(output.Items) > 0
}

// CollectEvidence collects API Gateway REST APIs as evidence.
func (c *APIGatewayCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
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
