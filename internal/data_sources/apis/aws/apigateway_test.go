package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	agtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockAPIGatewayClient struct {
	GetRestApisFunc    func(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error)
	GetStagesFunc      func(ctx context.Context, params *apigateway.GetStagesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error)
	GetAuthorizersFunc func(ctx context.Context, params *apigateway.GetAuthorizersInput, optFns ...func(*apigateway.Options)) (*apigateway.GetAuthorizersOutput, error)
}

func (m *MockAPIGatewayClient) GetRestApis(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	return m.GetRestApisFunc(ctx, params, optFns...)
}

func (m *MockAPIGatewayClient) GetStages(ctx context.Context, params *apigateway.GetStagesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
	if m.GetStagesFunc != nil {
		return m.GetStagesFunc(ctx, params, optFns...)
	}
	return &apigateway.GetStagesOutput{Item: []agtypes.Stage{}}, nil
}

func (m *MockAPIGatewayClient) GetAuthorizers(ctx context.Context, params *apigateway.GetAuthorizersInput, optFns ...func(*apigateway.Options)) (*apigateway.GetAuthorizersOutput, error) {
	if m.GetAuthorizersFunc != nil {
		return m.GetAuthorizersFunc(ctx, params, optFns...)
	}
	return &apigateway.GetAuthorizersOutput{Items: []agtypes.Authorizer{}}, nil
}

func TestAPIGatewayCollector_CollectAPIs(t *testing.T) {
	mock := &MockAPIGatewayClient{
		GetRestApisFunc: func(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
			return &apigateway.GetRestApisOutput{
				Items: []agtypes.RestApi{
					{Id: awssdk.String("abc123"), Name: awssdk.String("my-api")},
				},
			}, nil
		},
		GetStagesFunc: func(ctx context.Context, params *apigateway.GetStagesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
			return &apigateway.GetStagesOutput{
				Item: []agtypes.Stage{
					{
						StageName: awssdk.String("prod"),
						MethodSettings: map[string]agtypes.MethodSetting{
							"*/*": {LoggingLevel: awssdk.String("INFO")},
						},
						AccessLogSettings: &agtypes.AccessLogSettings{
							DestinationArn: awssdk.String("arn:aws:logs:us-east-1:123:log-group:api-logs"),
						},
					},
					{
						StageName: awssdk.String("dev"),
						MethodSettings: map[string]agtypes.MethodSetting{
							"*/*": {LoggingLevel: awssdk.String("OFF")},
						},
					},
				},
			}, nil
		},
	}

	collector := NewAPIGatewayCollector(mock)
	apis, err := collector.CollectAPIs(context.Background())

	require.NoError(t, err)
	require.Len(t, apis, 1)
	assert.Equal(t, "my-api", apis[0].Name)
	require.Len(t, apis[0].Stages, 2)

	assert.Equal(t, "prod", apis[0].Stages[0].StageName)
	assert.True(t, apis[0].Stages[0].LoggingEnabled)
	assert.True(t, apis[0].Stages[0].AccessLogEnabled)

	assert.Equal(t, "dev", apis[0].Stages[1].StageName)
	assert.False(t, apis[0].Stages[1].LoggingEnabled)
	assert.False(t, apis[0].Stages[1].AccessLogEnabled)
}

func TestAPIGatewayCollector_CollectAPIs_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockAPIGatewayClient{
		GetRestApisFunc: func(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
			callCount++
			if callCount == 1 {
				return &apigateway.GetRestApisOutput{
					Items: []agtypes.RestApi{
						{Id: awssdk.String("api-1"), Name: awssdk.String("first-api")},
					},
					Position: awssdk.String("next"),
				}, nil
			}
			return &apigateway.GetRestApisOutput{
				Items: []agtypes.RestApi{
					{Id: awssdk.String("api-2"), Name: awssdk.String("second-api")},
				},
			}, nil
		},
	}

	collector := NewAPIGatewayCollector(mock)
	apis, err := collector.CollectAPIs(context.Background())

	require.NoError(t, err)
	require.Len(t, apis, 2)
	assert.Equal(t, "first-api", apis[0].Name)
	assert.Equal(t, "second-api", apis[1].Name)
	assert.Equal(t, 2, callCount, "should have paginated with 2 API calls")
}

func TestAPIGatewayCollector_CollectAPIs_StagesError_FailSafe(t *testing.T) {
	mock := &MockAPIGatewayClient{
		GetRestApisFunc: func(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
			return &apigateway.GetRestApisOutput{
				Items: []agtypes.RestApi{
					{Id: awssdk.String("api-err"), Name: awssdk.String("error-api")},
				},
			}, nil
		},
		GetStagesFunc: func(ctx context.Context, params *apigateway.GetStagesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewAPIGatewayCollector(mock)
	apis, err := collector.CollectAPIs(context.Background())

	require.NoError(t, err, "should not fail when GetStages fails")
	require.Len(t, apis, 1)
	assert.Equal(t, "error-api", apis[0].Name)
	assert.Empty(t, apis[0].Stages, "stages should be empty when GetStages fails")
}

func TestAPIGatewayCollector_CollectAPIs_NoMethodSettings(t *testing.T) {
	mock := &MockAPIGatewayClient{
		GetRestApisFunc: func(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
			return &apigateway.GetRestApisOutput{
				Items: []agtypes.RestApi{
					{Id: awssdk.String("api-no-settings"), Name: awssdk.String("no-settings-api")},
				},
			}, nil
		},
		GetStagesFunc: func(ctx context.Context, params *apigateway.GetStagesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
			return &apigateway.GetStagesOutput{
				Item: []agtypes.Stage{
					{
						StageName:      awssdk.String("prod"),
						MethodSettings: map[string]agtypes.MethodSetting{},
						// No AccessLogSettings
					},
				},
			}, nil
		},
	}

	collector := NewAPIGatewayCollector(mock)
	apis, err := collector.CollectAPIs(context.Background())

	require.NoError(t, err)
	require.Len(t, apis, 1)
	require.Len(t, apis[0].Stages, 1)
	assert.False(t, apis[0].Stages[0].LoggingEnabled, "no method settings should mean logging disabled")
	assert.False(t, apis[0].Stages[0].AccessLogEnabled, "no access log settings should mean access logging disabled")
}

func TestAPIGatewayCollector_CollectEvidence(t *testing.T) {
	mock := &MockAPIGatewayClient{
		GetRestApisFunc: func(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
			return &apigateway.GetRestApisOutput{
				Items: []agtypes.RestApi{
					{Id: awssdk.String("api-ev"), Name: awssdk.String("ev-api")},
				},
			}, nil
		},
		GetStagesFunc: func(ctx context.Context, params *apigateway.GetStagesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
			return &apigateway.GetStagesOutput{
				Item: []agtypes.Stage{
					{StageName: awssdk.String("prod"), MethodSettings: map[string]agtypes.MethodSetting{
						"*/*": {LoggingLevel: awssdk.String("INFO")},
					}},
				},
			}, nil
		},
	}

	collector := NewAPIGatewayCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:apigateway:rest_api", ev[0].ResourceType)
	assert.Equal(t, "123456789012", ev[0].Metadata.AccountID)
}

func TestAPIGatewayCollector_CollectEvidence_Error(t *testing.T) {
	mock := &MockAPIGatewayClient{
		GetRestApisFunc: func(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
			return nil, errors.New("service unavailable")
		},
	}

	collector := NewAPIGatewayCollector(mock)
	_, err := collector.CollectEvidence(context.Background(), "123456789012")
	assert.Error(t, err)
}

func TestAPIGatewayCollector_CollectAPIs_Empty(t *testing.T) {
	mock := &MockAPIGatewayClient{
		GetRestApisFunc: func(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
			return &apigateway.GetRestApisOutput{Items: []agtypes.RestApi{}}, nil
		},
	}

	collector := NewAPIGatewayCollector(mock)
	apis, err := collector.CollectAPIs(context.Background())

	require.NoError(t, err)
	assert.Empty(t, apis)
}

func TestAPIGatewayCollector_CollectAPIs_Error(t *testing.T) {
	mock := &MockAPIGatewayClient{
		GetRestApisFunc: func(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewAPIGatewayCollector(mock)
	_, err := collector.CollectAPIs(context.Background())
	assert.Error(t, err)
}

func TestAPIGatewayAPI_ToEvidence(t *testing.T) {
	api := &APIGatewayAPI{APIID: "abc123", Name: "my-api"}
	ev := api.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:apigateway:rest_api", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "abc123")
}
