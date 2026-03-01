package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockGuardDutyClient implements GuardDutyClient for testing.
type MockGuardDutyClient struct {
	ListDetectorsFunc func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetDetectorFunc   func(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
}

func (m *MockGuardDutyClient) ListDetectors(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return m.ListDetectorsFunc(ctx, params, optFns...)
}

func (m *MockGuardDutyClient) GetDetector(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
	return m.GetDetectorFunc(ctx, params, optFns...)
}

func TestGuardDutyCollector_CollectStatus(t *testing.T) {
	tests := []struct {
		name        string
		detectorIDs []string
		detStatus   gdtypes.DetectorStatus
		listErr     error
		getErr      error
		wantEnabled bool
	}{
		{
			name:        "GuardDuty enabled",
			detectorIDs: []string{"det-123"},
			detStatus:   gdtypes.DetectorStatusEnabled,
			wantEnabled: true,
		},
		{
			name:        "GuardDuty disabled (suspended)",
			detectorIDs: []string{"det-123"},
			detStatus:   gdtypes.DetectorStatusDisabled,
			wantEnabled: false,
		},
		{
			name:        "no detectors",
			detectorIDs: []string{},
			wantEnabled: false,
		},
		{
			name:        "ListDetectors error (fail-safe)",
			listErr:     errors.New("access denied"),
			wantEnabled: false,
		},
		{
			name:        "GetDetector error (fail-safe)",
			detectorIDs: []string{"det-123"},
			getErr:      errors.New("not found"),
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockGuardDutyClient{
				ListDetectorsFunc: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
					if tt.listErr != nil {
						return nil, tt.listErr
					}
					return &guardduty.ListDetectorsOutput{DetectorIds: tt.detectorIDs}, nil
				},
				GetDetectorFunc: func(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
					if tt.getErr != nil {
						return nil, tt.getErr
					}
					return &guardduty.GetDetectorOutput{Status: tt.detStatus}, nil
				},
			}

			collector := NewGuardDutyCollector(mock, "us-east-1")
			status, err := collector.CollectStatus(context.Background())

			require.NoError(t, err, "CollectStatus should never return an error")
			assert.Equal(t, tt.wantEnabled, status.Enabled)
			assert.Equal(t, "us-east-1", status.Region)

			if tt.name == "GuardDuty enabled" {
				assert.Equal(t, "det-123", status.DetectorID)
				assert.Equal(t, "ENABLED", status.Status)
			}
		})
	}
}

func TestGuardDutyCollector_CollectEvidence(t *testing.T) {
	mock := &MockGuardDutyClient{
		ListDetectorsFunc: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return &guardduty.ListDetectorsOutput{DetectorIds: []string{"det-1"}}, nil
		},
		GetDetectorFunc: func(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
			return &guardduty.GetDetectorOutput{Status: gdtypes.DetectorStatusEnabled}, nil
		},
	}

	collector := NewGuardDutyCollector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.Len(t, ev, 1)
	assert.Equal(t, "aws:guardduty:detector", ev[0].ResourceType)
}

func TestGuardDutyStatus_ToEvidence(t *testing.T) {
	status := &GuardDutyStatus{
		Enabled:    true,
		DetectorID: "det-1",
		Region:     "us-east-1",
	}

	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:guardduty:detector", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "us-east-1")
	assert.NotEmpty(t, ev.Hash)
}

// Verify the unused import is needed
var _ = awssdk.String

// --- Negative Tests ---

func TestGuardDutyCollector_CollectStatus_MultipleDetectors(t *testing.T) {
	// When multiple detectors exist, only the first is checked
	mock := &MockGuardDutyClient{
		ListDetectorsFunc: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return &guardduty.ListDetectorsOutput{DetectorIds: []string{"det-1", "det-2", "det-3"}}, nil
		},
		GetDetectorFunc: func(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
			return &guardduty.GetDetectorOutput{Status: gdtypes.DetectorStatusEnabled}, nil
		},
	}

	collector := NewGuardDutyCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.True(t, status.Enabled)
	assert.Equal(t, 3, status.DetectorCount)
	assert.Equal(t, "det-1", status.DetectorID, "should use first detector")
}

func TestGuardDutyCollector_CollectEvidence_ListDetectorsError(t *testing.T) {
	// ListDetectors error is fail-safe — should still return evidence with Enabled=false
	mock := &MockGuardDutyClient{
		ListDetectorsFunc: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return nil, errors.New("service unavailable")
		},
		GetDetectorFunc: func(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
			t.Fatal("GetDetector should not be called when ListDetectors fails")
			return nil, nil
		},
	}

	collector := NewGuardDutyCollector(mock, "us-west-2")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err, "ListDetectors error is fail-safe")
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:guardduty:detector", ev[0].ResourceType)
}
