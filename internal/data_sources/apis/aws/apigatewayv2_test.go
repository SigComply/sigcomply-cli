package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockAPIGatewayV2Client struct {
	GetApisFunc   func(ctx context.Context, params *apigatewayv2.GetApisInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error)
	GetStagesFunc func(ctx context.Context, params *apigatewayv2.GetStagesInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error)
}

func (m *MockAPIGatewayV2Client) GetApis(ctx context.Context, params *apigatewayv2.GetApisInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	return m.GetApisFunc(ctx, params, optFns...)
}

func (m *MockAPIGatewayV2Client) GetStages(ctx context.Context, params *apigatewayv2.GetStagesInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error) {
	if m.GetStagesFunc != nil {
		return m.GetStagesFunc(ctx, params, optFns...)
	}
	return &apigatewayv2.GetStagesOutput{}, nil
}

func TestAPIGatewayV2Collector_CollectAPIs(t *testing.T) {
	mock := &MockAPIGatewayV2Client{
		GetApisFunc: func(ctx context.Context, params *apigatewayv2.GetApisInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
			return &apigatewayv2.GetApisOutput{
				Items: []apigwv2types.Api{
					{
						ApiId: awssdk.String("api-logged"),
						Name:  awssdk.String("LoggedAPI"),
					},
					{
						ApiId: awssdk.String("api-unlogged"),
						Name:  awssdk.String("UnloggedAPI"),
					},
				},
			}, nil
		},
		GetStagesFunc: func(ctx context.Context, params *apigatewayv2.GetStagesInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error) {
			if awssdk.ToString(params.ApiId) == "api-logged" {
				return &apigatewayv2.GetStagesOutput{
					Items: []apigwv2types.Stage{
						{
							StageName: awssdk.String("prod"),
							AccessLogSettings: &apigwv2types.AccessLogSettings{
								DestinationArn: awssdk.String("arn:aws:logs:us-east-1:123:log-group:/api/prod"),
							},
						},
					},
				}, nil
			}
			return &apigatewayv2.GetStagesOutput{
				Items: []apigwv2types.Stage{
					{StageName: awssdk.String("prod")},
				},
			}, nil
		},
	}

	collector := NewAPIGatewayV2Collector(mock)
	apis, err := collector.CollectAPIs(context.Background())

	require.NoError(t, err)
	require.Len(t, apis, 2)

	assert.Equal(t, "LoggedAPI", apis[0].Name)
	assert.True(t, apis[0].AccessLoggingEnabled)

	assert.Equal(t, "UnloggedAPI", apis[1].Name)
	assert.False(t, apis[1].AccessLoggingEnabled)
}

func TestAPIGatewayV2Collector_CollectEvidence(t *testing.T) {
	mock := &MockAPIGatewayV2Client{
		GetApisFunc: func(ctx context.Context, params *apigatewayv2.GetApisInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
			return &apigatewayv2.GetApisOutput{
				Items: []apigwv2types.Api{
					{ApiId: awssdk.String("api-1"), Name: awssdk.String("API1")},
				},
			}, nil
		},
	}

	collector := NewAPIGatewayV2Collector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:apigateway:v2-api", ev[0].ResourceType)
}
