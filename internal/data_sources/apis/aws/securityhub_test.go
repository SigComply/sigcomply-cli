package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockSecurityHubClient struct {
	DescribeHubFunc func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
}

func (m *MockSecurityHubClient) DescribeHub(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
	return m.DescribeHubFunc(ctx, params, optFns...)
}

func TestSecurityHubCollector_CollectStatus(t *testing.T) {
	tests := []struct {
		name        string
		hubARN      *string
		err         error
		wantEnabled bool
	}{
		{
			name:        "Security Hub enabled",
			hubARN:      strPtr("arn:aws:securityhub:us-east-1:123:hub/default"),
			wantEnabled: true,
		},
		{
			name:        "Security Hub not enabled (error)",
			err:         errors.New("not subscribed"),
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockSecurityHubClient{
				DescribeHubFunc: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
					if tt.err != nil {
						return nil, tt.err
					}
					return &securityhub.DescribeHubOutput{HubArn: tt.hubARN}, nil
				},
			}

			collector := NewSecurityHubCollector(mock, "us-east-1")
			status, err := collector.CollectStatus(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tt.wantEnabled, status.Enabled)
			assert.Equal(t, "us-east-1", status.Region)
		})
	}
}

func TestSecurityHubCollector_CollectEvidence(t *testing.T) {
	mock := &MockSecurityHubClient{
		DescribeHubFunc: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
			return &securityhub.DescribeHubOutput{HubArn: strPtr("arn:aws:securityhub:us-east-1:123:hub/default")}, nil
		},
	}

	collector := NewSecurityHubCollector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.Len(t, ev, 1)
	assert.Equal(t, "aws:securityhub:hub", ev[0].ResourceType)
}

func TestSecurityHubStatus_ToEvidence(t *testing.T) {
	status := &SecurityHubStatus{Enabled: true, Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:securityhub:hub", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}

func strPtr(s string) *string { return &s }
