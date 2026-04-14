package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockCloudWatchAlarmsClient struct {
	DescribeAlarmsFunc func(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

func (m *MockCloudWatchAlarmsClient) DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	return m.DescribeAlarmsFunc(ctx, params, optFns...)
}

func TestCloudWatchAlarmsCollector_CollectAlarmConfig(t *testing.T) {
	tests := []struct {
		name              string
		alarms            []cwtypes.MetricAlarm
		err               error
		wantAllConfigured bool
		wantUnauthorized  bool
		wantRoot          bool
		wantSignIn        bool
	}{
		{
			name: "all critical alarms configured",
			alarms: []cwtypes.MetricAlarm{
				{AlarmName: awssdk.String("UnauthorizedAPICalls"), AlarmDescription: awssdk.String("Detect unauthorized API calls")},
				{AlarmName: awssdk.String("RootAccountUsage"), AlarmDescription: awssdk.String("Root account usage")},
				{AlarmName: awssdk.String("ConsoleSignInFailures"), AlarmDescription: awssdk.String("Failed sign-in attempts")},
			},
			wantAllConfigured: true,
			wantUnauthorized:  true,
			wantRoot:          true,
			wantSignIn:        true,
		},
		{
			name: "missing some alarms",
			alarms: []cwtypes.MetricAlarm{
				{AlarmName: awssdk.String("UnauthorizedAPICalls")},
			},
			wantAllConfigured: false,
			wantUnauthorized:  true,
		},
		{
			name:              "no alarms",
			alarms:            []cwtypes.MetricAlarm{},
			wantAllConfigured: false,
		},
		{
			name:              "API error (fail-safe)",
			err:               errors.New("access denied"),
			wantAllConfigured: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockCloudWatchAlarmsClient{
				DescribeAlarmsFunc: func(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
					if tt.err != nil {
						return nil, tt.err
					}
					return &cloudwatch.DescribeAlarmsOutput{MetricAlarms: tt.alarms}, nil
				},
			}

			collector := NewCloudWatchAlarmsCollector(mock, "us-east-1")
			config, err := collector.CollectAlarmConfig(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tt.wantAllConfigured, config.AllCriticalAlarmsConfigured)
			assert.Equal(t, tt.wantUnauthorized, config.HasUnauthorizedAPICalls)
			assert.Equal(t, tt.wantRoot, config.HasRootUsage)
			assert.Equal(t, tt.wantSignIn, config.HasConsoleSignInFailures)
		})
	}
}

func TestCloudWatchAlarmsCollector_CollectEvidence(t *testing.T) {
	mock := &MockCloudWatchAlarmsClient{
		DescribeAlarmsFunc: func(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
			return &cloudwatch.DescribeAlarmsOutput{}, nil
		},
	}

	collector := NewCloudWatchAlarmsCollector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.Len(t, ev, 16) // 1 alarm config + 15 CIS metric filters
	assert.Equal(t, "aws:cloudwatch:alarm-config", ev[0].ResourceType)
	assert.Equal(t, "aws:cloudwatch:cis-metric-filter", ev[1].ResourceType)
}
