package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockSSMClient struct {
	DescribeInstanceInformationFunc func(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error)
	GetServiceSettingFunc           func(ctx context.Context, params *ssm.GetServiceSettingInput, optFns ...func(*ssm.Options)) (*ssm.GetServiceSettingOutput, error)
}

func (m *MockSSMClient) DescribeInstanceInformation(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	return m.DescribeInstanceInformationFunc(ctx, params, optFns...)
}

func (m *MockSSMClient) GetServiceSetting(ctx context.Context, params *ssm.GetServiceSettingInput, optFns ...func(*ssm.Options)) (*ssm.GetServiceSettingOutput, error) {
	if m.GetServiceSettingFunc != nil {
		return m.GetServiceSettingFunc(ctx, params, optFns...)
	}
	return &ssm.GetServiceSettingOutput{ServiceSetting: &ssmtypes.ServiceSetting{SettingValue: awssdk.String("Standard")}}, nil
}

func TestSSMCollector_CollectStatus(t *testing.T) {
	tests := []struct {
		name              string
		instances         []ssmtypes.InstanceInformation
		instanceErr       error
		wantSessionMgr    bool
		wantInstanceCount int
	}{
		{
			name: "managed instances present",
			instances: []ssmtypes.InstanceInformation{
				{InstanceId: awssdk.String("i-123")},
				{InstanceId: awssdk.String("i-456")},
			},
			wantSessionMgr:    true,
			wantInstanceCount: 2,
		},
		{
			name:              "no managed instances",
			instances:         []ssmtypes.InstanceInformation{},
			wantSessionMgr:    false,
			wantInstanceCount: 0,
		},
		{
			name:              "API error (fail-safe)",
			instanceErr:       errors.New("access denied"),
			wantSessionMgr:    false,
			wantInstanceCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockSSMClient{
				DescribeInstanceInformationFunc: func(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
					if tt.instanceErr != nil {
						return nil, tt.instanceErr
					}
					return &ssm.DescribeInstanceInformationOutput{InstanceInformationList: tt.instances}, nil
				},
			}

			collector := NewSSMCollector(mock, "us-east-1")
			status, err := collector.CollectStatus(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tt.wantSessionMgr, status.SessionManagerEnabled)
			assert.Equal(t, tt.wantInstanceCount, status.ManagedInstanceCount)
		})
	}
}

func TestSSMStatus_ToEvidence(t *testing.T) {
	status := &SSMStatus{ManagedInstanceCount: 5, SessionManagerEnabled: true, Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:ssm:status", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
