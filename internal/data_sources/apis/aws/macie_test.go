package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macietypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockMacieClient struct {
	GetMacieSessionFunc func(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error)
}

func (m *MockMacieClient) GetMacieSession(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error) {
	return m.GetMacieSessionFunc(ctx, params, optFns...)
}

func TestMacieCollector_CollectStatus(t *testing.T) {
	tests := []struct {
		name        string
		status      macietypes.MacieStatus
		err         error
		wantEnabled bool
	}{
		{
			name:        "Macie enabled",
			status:      macietypes.MacieStatusEnabled,
			wantEnabled: true,
		},
		{
			name:        "Macie paused",
			status:      macietypes.MacieStatusPaused,
			wantEnabled: false,
		},
		{
			name:        "not available (fail-safe)",
			err:         errors.New("not enabled"),
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockMacieClient{
				GetMacieSessionFunc: func(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error) {
					if tt.err != nil {
						return nil, tt.err
					}
					return &macie2.GetMacieSessionOutput{Status: tt.status}, nil
				},
			}

			collector := NewMacieCollector(mock, "us-east-1")
			status, err := collector.CollectStatus(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tt.wantEnabled, status.Enabled)
		})
	}
}

func TestMacieStatus_ToEvidence(t *testing.T) {
	status := &MacieStatus{Enabled: true, Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:macie2:session", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
