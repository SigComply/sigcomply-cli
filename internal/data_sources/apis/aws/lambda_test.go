package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockLambdaClient struct {
	ListFunctionsFunc func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetPolicyFunc     func(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

func (m *MockLambdaClient) ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return m.ListFunctionsFunc(ctx, params, optFns...)
}

func (m *MockLambdaClient) GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	if m.GetPolicyFunc != nil {
		return m.GetPolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ResourceNotFoundException")
}

func TestLambdaCollector_CollectFunctions(t *testing.T) {
	mock := &MockLambdaClient{
		ListFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return &lambda.ListFunctionsOutput{
				Functions: []lambdatypes.FunctionConfiguration{
					{
						FunctionName: awssdk.String("my-func"),
						FunctionArn:  awssdk.String("arn:aws:lambda:us-east-1:123:function:my-func"),
						Runtime:      lambdatypes.RuntimePython312,
					},
					{
						FunctionName: awssdk.String("old-func"),
						FunctionArn:  awssdk.String("arn:aws:lambda:us-east-1:123:function:old-func"),
						Runtime:      lambdatypes.RuntimePython36,
					},
				},
			}, nil
		},
	}

	collector := NewLambdaCollector(mock)
	functions, err := collector.CollectFunctions(context.Background())

	require.NoError(t, err)
	require.Len(t, functions, 2)

	assert.Equal(t, "my-func", functions[0].Name)
	assert.False(t, functions[0].RuntimeDeprecated)

	assert.Equal(t, "old-func", functions[1].Name)
	assert.True(t, functions[1].RuntimeDeprecated)
}

func TestLambdaCollector_CollectFunctions_PublicAccess(t *testing.T) {
	mock := &MockLambdaClient{
		ListFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return &lambda.ListFunctionsOutput{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionName: awssdk.String("public-func"), FunctionArn: awssdk.String("arn:aws:lambda:us-east-1:123:function:public-func"), Runtime: lambdatypes.RuntimePython312},
				},
			}, nil
		},
		GetPolicyFunc: func(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
			return &lambda.GetPolicyOutput{Policy: awssdk.String(`{"Statement":[{"Principal":"*"}]}`)}, nil
		},
	}

	collector := NewLambdaCollector(mock)
	functions, err := collector.CollectFunctions(context.Background())

	require.NoError(t, err)
	require.Len(t, functions, 1)
	assert.True(t, functions[0].PubliclyAccessible)
}

func TestLambdaCollector_CollectFunctions_Error(t *testing.T) {
	mock := &MockLambdaClient{
		ListFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewLambdaCollector(mock)
	_, err := collector.CollectFunctions(context.Background())
	assert.Error(t, err)
}

func TestLambdaFunction_ToEvidence(t *testing.T) {
	fn := &LambdaFunction{Name: "test", ARN: "arn:aws:lambda:us-east-1:123:function:test", Runtime: "python3.12"}
	ev := fn.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:lambda:function", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
