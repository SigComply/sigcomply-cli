package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cstypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockConfigServiceClient implements ConfigServiceClient for testing.
type MockConfigServiceClient struct {
	DescribeConfigurationRecordersFunc      func(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	DescribeConfigurationRecorderStatusFunc func(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error)
}

func (m *MockConfigServiceClient) DescribeConfigurationRecorders(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
	return m.DescribeConfigurationRecordersFunc(ctx, params, optFns...)
}

func (m *MockConfigServiceClient) DescribeConfigurationRecorderStatus(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
	return m.DescribeConfigurationRecorderStatusFunc(ctx, params, optFns...)
}

func TestConfigCollector_CollectStatus(t *testing.T) {
	tests := []struct {
		name        string
		recorders   []cstypes.ConfigurationRecorder
		statuses    []cstypes.ConfigurationRecorderStatus
		recErr      error
		statusErr   error
		wantEnabled bool
		wantCount   int
	}{
		{
			name: "Config enabled and recording",
			recorders: []cstypes.ConfigurationRecorder{
				{
					Name: awssdk.String("default"),
					RecordingGroup: &cstypes.RecordingGroup{
						AllSupported: true,
					},
				},
			},
			statuses: []cstypes.ConfigurationRecorderStatus{
				{Name: awssdk.String("default"), Recording: true},
			},
			wantEnabled: true,
			wantCount:   1,
		},
		{
			name: "Config recorder exists but not recording",
			recorders: []cstypes.ConfigurationRecorder{
				{Name: awssdk.String("default")},
			},
			statuses: []cstypes.ConfigurationRecorderStatus{
				{Name: awssdk.String("default"), Recording: false},
			},
			wantEnabled: false,
			wantCount:   1,
		},
		{
			name:        "no recorders configured",
			recorders:   []cstypes.ConfigurationRecorder{},
			wantEnabled: false,
			wantCount:   0,
		},
		{
			name:        "DescribeRecorders error (fail-safe)",
			recErr:      errors.New("access denied"),
			wantEnabled: false,
			wantCount:   0,
		},
		{
			name: "DescribeRecorderStatus error (fail-safe)",
			recorders: []cstypes.ConfigurationRecorder{
				{Name: awssdk.String("default")},
			},
			statusErr:   errors.New("access denied"),
			wantEnabled: false,
			wantCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockConfigServiceClient{
				DescribeConfigurationRecordersFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
					if tt.recErr != nil {
						return nil, tt.recErr
					}
					return &configservice.DescribeConfigurationRecordersOutput{ConfigurationRecorders: tt.recorders}, nil
				},
				DescribeConfigurationRecorderStatusFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
					if tt.statusErr != nil {
						return nil, tt.statusErr
					}
					return &configservice.DescribeConfigurationRecorderStatusOutput{ConfigurationRecordersStatus: tt.statuses}, nil
				},
			}

			collector := NewConfigCollector(mock, "us-east-1")
			status, err := collector.CollectStatus(context.Background())

			require.NoError(t, err, "CollectStatus should never return an error")
			assert.Equal(t, tt.wantEnabled, status.Enabled)
			assert.Len(t, status.Recorders, tt.wantCount)
			assert.Equal(t, "us-east-1", status.Region)

			if tt.name == "Config enabled and recording" {
				assert.True(t, status.Recorders[0].AllSupported)
				assert.True(t, status.Recorders[0].Recording)
			}
		})
	}
}

func TestConfigCollector_CollectEvidence(t *testing.T) {
	mock := &MockConfigServiceClient{
		DescribeConfigurationRecordersFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
			return &configservice.DescribeConfigurationRecordersOutput{
				ConfigurationRecorders: []cstypes.ConfigurationRecorder{
					{Name: awssdk.String("default"), RecordingGroup: &cstypes.RecordingGroup{AllSupported: true}},
				},
			}, nil
		},
		DescribeConfigurationRecorderStatusFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
			return &configservice.DescribeConfigurationRecorderStatusOutput{
				ConfigurationRecordersStatus: []cstypes.ConfigurationRecorderStatus{
					{Name: awssdk.String("default"), Recording: true},
				},
			}, nil
		},
	}

	collector := NewConfigCollector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.Len(t, ev, 1)
	assert.Equal(t, "aws:config:recorder", ev[0].ResourceType)
}

func TestConfigStatus_ToEvidence(t *testing.T) {
	status := &ConfigStatus{
		Enabled: true,
		Region:  "us-east-1",
		Recorders: []ConfigRecorder{
			{Name: "default", Recording: true},
		},
	}

	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:config:recorder", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "us-east-1")
	assert.NotEmpty(t, ev.Hash)
}

// --- Negative Tests ---

func TestConfigCollector_CollectStatus_MultipleRecorders(t *testing.T) {
	mock := &MockConfigServiceClient{
		DescribeConfigurationRecordersFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
			return &configservice.DescribeConfigurationRecordersOutput{
				ConfigurationRecorders: []cstypes.ConfigurationRecorder{
					{Name: awssdk.String("recorder-1"), RecordingGroup: &cstypes.RecordingGroup{AllSupported: true}},
					{Name: awssdk.String("recorder-2"), RecordingGroup: &cstypes.RecordingGroup{AllSupported: false}},
				},
			}, nil
		},
		DescribeConfigurationRecorderStatusFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
			return &configservice.DescribeConfigurationRecorderStatusOutput{
				ConfigurationRecordersStatus: []cstypes.ConfigurationRecorderStatus{
					{Name: awssdk.String("recorder-1"), Recording: true},
					{Name: awssdk.String("recorder-2"), Recording: false},
				},
			}, nil
		},
	}

	collector := NewConfigCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.True(t, status.Enabled, "at least one recorder is recording")
	assert.Len(t, status.Recorders, 2)
	assert.True(t, status.Recorders[0].Recording)
	assert.True(t, status.Recorders[0].AllSupported)
	assert.False(t, status.Recorders[1].Recording)
	assert.False(t, status.Recorders[1].AllSupported)
}

func TestConfigCollector_CollectStatus_NilRecordingGroup(t *testing.T) {
	mock := &MockConfigServiceClient{
		DescribeConfigurationRecordersFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
			return &configservice.DescribeConfigurationRecordersOutput{
				ConfigurationRecorders: []cstypes.ConfigurationRecorder{
					{Name: awssdk.String("recorder"), RecordingGroup: nil},
				},
			}, nil
		},
		DescribeConfigurationRecorderStatusFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
			return &configservice.DescribeConfigurationRecorderStatusOutput{
				ConfigurationRecordersStatus: []cstypes.ConfigurationRecorderStatus{
					{Name: awssdk.String("recorder"), Recording: true},
				},
			}, nil
		},
	}

	collector := NewConfigCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err, "nil RecordingGroup should be handled")
	assert.True(t, status.Enabled)
	assert.Len(t, status.Recorders, 1)
	assert.False(t, status.Recorders[0].AllSupported, "nil RecordingGroup means AllSupported is false")
}

func TestConfigCollector_CollectStatus_RecorderExistsButNoStatus(t *testing.T) {
	mock := &MockConfigServiceClient{
		DescribeConfigurationRecordersFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
			return &configservice.DescribeConfigurationRecordersOutput{
				ConfigurationRecorders: []cstypes.ConfigurationRecorder{
					{Name: awssdk.String("orphan-recorder")},
				},
			}, nil
		},
		DescribeConfigurationRecorderStatusFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
			// No status entries for this recorder
			return &configservice.DescribeConfigurationRecorderStatusOutput{
				ConfigurationRecordersStatus: []cstypes.ConfigurationRecorderStatus{},
			}, nil
		},
	}

	collector := NewConfigCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.False(t, status.Enabled, "no status means not recording")
	assert.Len(t, status.Recorders, 1)
	assert.False(t, status.Recorders[0].Recording, "missing status entry means not recording")
}

func TestConfigCollector_CollectEvidence_FailSafe(t *testing.T) {
	// Both describe calls fail — should still return evidence with Enabled=false
	mock := &MockConfigServiceClient{
		DescribeConfigurationRecordersFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
			return nil, errors.New("service unavailable")
		},
		DescribeConfigurationRecorderStatusFunc: func(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
			t.Fatal("should not be called when DescribeRecorders fails")
			return nil, nil
		},
	}

	collector := NewConfigCollector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err, "fail-safe should not return error")
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:config:recorder", ev[0].ResourceType)
}
