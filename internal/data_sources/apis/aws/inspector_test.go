package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	i2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockInspectorClient struct {
	BatchGetAccountStatusFunc func(ctx context.Context, params *inspector2.BatchGetAccountStatusInput, optFns ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error)
}

func (m *MockInspectorClient) BatchGetAccountStatus(ctx context.Context, params *inspector2.BatchGetAccountStatusInput, optFns ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
	return m.BatchGetAccountStatusFunc(ctx, params, optFns...)
}

func TestInspectorCollector_Enabled(t *testing.T) {
	mock := &MockInspectorClient{
		BatchGetAccountStatusFunc: func(ctx context.Context, params *inspector2.BatchGetAccountStatusInput, optFns ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
			return &inspector2.BatchGetAccountStatusOutput{
				Accounts: []i2types.AccountState{
					{
						ResourceState: &i2types.ResourceState{
							Ec2:    &i2types.State{Status: i2types.StatusEnabled},
							Ecr:    &i2types.State{Status: i2types.StatusEnabled},
							Lambda: &i2types.State{Status: i2types.StatusDisabled},
						},
					},
				},
			}, nil
		},
	}

	collector := NewInspectorCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.True(t, status.Enabled)
	assert.True(t, status.EC2Scanning)
	assert.True(t, status.ECRScanning)
	assert.False(t, status.LambdaScanning)
}

func TestInspectorCollector_Disabled(t *testing.T) {
	mock := &MockInspectorClient{
		BatchGetAccountStatusFunc: func(ctx context.Context, params *inspector2.BatchGetAccountStatusInput, optFns ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
			return &inspector2.BatchGetAccountStatusOutput{
				Accounts: []i2types.AccountState{
					{
						ResourceState: &i2types.ResourceState{
							Ec2:    &i2types.State{Status: i2types.StatusDisabled},
							Ecr:    &i2types.State{Status: i2types.StatusDisabled},
							Lambda: &i2types.State{Status: i2types.StatusDisabled},
						},
					},
				},
			}, nil
		},
	}

	collector := NewInspectorCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.False(t, status.Enabled)
}

func TestInspectorCollector_Error_FailSafe(t *testing.T) {
	mock := &MockInspectorClient{
		BatchGetAccountStatusFunc: func(ctx context.Context, params *inspector2.BatchGetAccountStatusInput, optFns ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewInspectorCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.False(t, status.Enabled)
}

func TestInspectorStatus_ToEvidence(t *testing.T) {
	status := &InspectorStatus{Enabled: true, Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:inspector:status", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
