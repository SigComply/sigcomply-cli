package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockRedshiftServerlessClient struct {
	ListWorkgroupsFunc func(ctx context.Context, params *redshiftserverless.ListWorkgroupsInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListWorkgroupsOutput, error)
	ListNamespacesFunc func(ctx context.Context, params *redshiftserverless.ListNamespacesInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListNamespacesOutput, error)
}

func (m *MockRedshiftServerlessClient) ListWorkgroups(ctx context.Context, params *redshiftserverless.ListWorkgroupsInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListWorkgroupsOutput, error) {
	return m.ListWorkgroupsFunc(ctx, params, optFns...)
}

func (m *MockRedshiftServerlessClient) ListNamespaces(ctx context.Context, params *redshiftserverless.ListNamespacesInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListNamespacesOutput, error) {
	if m.ListNamespacesFunc != nil {
		return m.ListNamespacesFunc(ctx, params, optFns...)
	}
	return &redshiftserverless.ListNamespacesOutput{}, nil
}

func TestRedshiftServerlessCollector_CollectWorkgroups(t *testing.T) {
	mock := &MockRedshiftServerlessClient{
		ListWorkgroupsFunc: func(ctx context.Context, params *redshiftserverless.ListWorkgroupsInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListWorkgroupsOutput, error) {
			return &redshiftserverless.ListWorkgroupsOutput{
				Workgroups: []rsstypes.Workgroup{
					{
						WorkgroupName:      awssdk.String("prod-wg"),
						WorkgroupArn:       awssdk.String("arn:aws:redshift-serverless:us-east-1:123:workgroup/prod-wg"),
						PubliclyAccessible: awssdk.Bool(false),
						NamespaceName:      awssdk.String("prod-ns"),
					},
					{
						WorkgroupName:      awssdk.String("dev-wg"),
						WorkgroupArn:       awssdk.String("arn:aws:redshift-serverless:us-east-1:123:workgroup/dev-wg"),
						PubliclyAccessible: awssdk.Bool(true),
						NamespaceName:      awssdk.String("dev-ns"),
					},
				},
			}, nil
		},
		ListNamespacesFunc: func(ctx context.Context, params *redshiftserverless.ListNamespacesInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListNamespacesOutput, error) {
			return &redshiftserverless.ListNamespacesOutput{
				Namespaces: []rsstypes.Namespace{
					{
						NamespaceName: awssdk.String("prod-ns"),
						KmsKeyId:      awssdk.String("arn:aws:kms:us-east-1:123:key/abc"),
					},
					{
						NamespaceName: awssdk.String("dev-ns"),
					},
				},
			}, nil
		},
	}

	collector := NewRedshiftServerlessCollector(mock)
	workgroups, err := collector.CollectWorkgroups(context.Background())

	require.NoError(t, err)
	require.Len(t, workgroups, 2)

	assert.Equal(t, "prod-wg", workgroups[0].Name)
	assert.False(t, workgroups[0].PubliclyAccessible)
	assert.True(t, workgroups[0].Encrypted)

	assert.Equal(t, "dev-wg", workgroups[1].Name)
	assert.True(t, workgroups[1].PubliclyAccessible)
	assert.False(t, workgroups[1].Encrypted)
}

func TestRedshiftServerlessCollector_CollectEvidence(t *testing.T) {
	mock := &MockRedshiftServerlessClient{
		ListWorkgroupsFunc: func(ctx context.Context, params *redshiftserverless.ListWorkgroupsInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListWorkgroupsOutput, error) {
			return &redshiftserverless.ListWorkgroupsOutput{
				Workgroups: []rsstypes.Workgroup{
					{
						WorkgroupName:      awssdk.String("wg"),
						WorkgroupArn:       awssdk.String("arn:aws:redshift-serverless:us-east-1:123:workgroup/wg"),
						PubliclyAccessible: awssdk.Bool(false),
						NamespaceName:      awssdk.String("ns"),
					},
				},
			}, nil
		},
	}

	collector := NewRedshiftServerlessCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:redshift-serverless:workgroup", ev[0].ResourceType)
}
