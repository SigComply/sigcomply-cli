package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsyncTypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockAppSyncClient struct {
	ListGraphqlApisFunc func(ctx context.Context, params *appsync.ListGraphqlApisInput, optFns ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error)
}

func (m *MockAppSyncClient) ListGraphqlApis(ctx context.Context, params *appsync.ListGraphqlApisInput, optFns ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error) {
	return m.ListGraphqlApisFunc(ctx, params, optFns...)
}

func TestAppSyncCollector_CollectAPIs(t *testing.T) {
	mock := &MockAppSyncClient{
		ListGraphqlApisFunc: func(ctx context.Context, params *appsync.ListGraphqlApisInput, optFns ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error) {
			return &appsync.ListGraphqlApisOutput{
				GraphqlApis: []appsyncTypes.GraphqlApi{
					{
						Name: awssdk.String("logged-api"),
						Arn:  awssdk.String("arn:aws:appsync:us-east-1:123:apis/abc"),
						LogConfig: &appsyncTypes.LogConfig{
							FieldLogLevel: appsyncTypes.FieldLogLevelAll,
						},
					},
					{
						Name: awssdk.String("unlogged-api"),
						Arn:  awssdk.String("arn:aws:appsync:us-east-1:123:apis/def"),
					},
				},
			}, nil
		},
	}

	collector := NewAppSyncCollector(mock)
	apis, err := collector.CollectAPIs(context.Background())

	require.NoError(t, err)
	require.Len(t, apis, 2)

	assert.Equal(t, "logged-api", apis[0].Name)
	assert.True(t, apis[0].LoggingEnabled)

	assert.Equal(t, "unlogged-api", apis[1].Name)
	assert.False(t, apis[1].LoggingEnabled)
}

func TestAppSyncCollector_CollectEvidence(t *testing.T) {
	mock := &MockAppSyncClient{
		ListGraphqlApisFunc: func(ctx context.Context, params *appsync.ListGraphqlApisInput, optFns ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error) {
			return &appsync.ListGraphqlApisOutput{
				GraphqlApis: []appsyncTypes.GraphqlApi{
					{
						Name: awssdk.String("api"),
						Arn:  awssdk.String("arn:aws:appsync:us-east-1:123:apis/abc"),
					},
				},
			}, nil
		},
	}

	collector := NewAppSyncCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:appsync:api", ev[0].ResourceType)
}
