package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockIdentityCenterClient struct {
	ListInstancesFunc func(ctx context.Context, params *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
}

func (m *MockIdentityCenterClient) ListInstances(ctx context.Context, params *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	return m.ListInstancesFunc(ctx, params, optFns...)
}

func TestIdentityCenterCollector_Enabled(t *testing.T) {
	mock := &MockIdentityCenterClient{
		ListInstancesFunc: func(ctx context.Context, params *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
			return &ssoadmin.ListInstancesOutput{
				Instances: []ssotypes.InstanceMetadata{
					{InstanceArn: awssdk.String("arn:aws:sso:::instance/ssoins-12345")},
				},
			}, nil
		},
	}

	collector := NewIdentityCenterCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.True(t, status.Enabled)
	assert.Equal(t, "arn:aws:sso:::instance/ssoins-12345", status.InstanceARN)
}

func TestIdentityCenterCollector_Disabled(t *testing.T) {
	mock := &MockIdentityCenterClient{
		ListInstancesFunc: func(ctx context.Context, params *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
			return &ssoadmin.ListInstancesOutput{
				Instances: []ssotypes.InstanceMetadata{},
			}, nil
		},
	}

	collector := NewIdentityCenterCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.False(t, status.Enabled)
	assert.Empty(t, status.InstanceARN)
}

func TestIdentityCenterCollector_Error_FailSafe(t *testing.T) {
	mock := &MockIdentityCenterClient{
		ListInstancesFunc: func(ctx context.Context, params *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewIdentityCenterCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.False(t, status.Enabled)
}

func TestIdentityCenterStatus_ToEvidence(t *testing.T) {
	status := &IdentityCenterStatus{Enabled: true, InstanceARN: "arn:aws:sso:::instance/ssoins-12345", Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:identitycenter:status", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
