package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockAccessAnalyzerClient struct {
	ListAnalyzersFunc func(ctx context.Context, params *accessanalyzer.ListAnalyzersInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error)
}

func (m *MockAccessAnalyzerClient) ListAnalyzers(ctx context.Context, params *accessanalyzer.ListAnalyzersInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
	return m.ListAnalyzersFunc(ctx, params, optFns...)
}

func TestAccessAnalyzerCollector_Enabled(t *testing.T) {
	mock := &MockAccessAnalyzerClient{
		ListAnalyzersFunc: func(ctx context.Context, params *accessanalyzer.ListAnalyzersInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
			return &accessanalyzer.ListAnalyzersOutput{
				Analyzers: []aatypes.AnalyzerSummary{
					{
						Name: strPtr("account-analyzer"),
						Type: aatypes.TypeAccount,
					},
				},
			}, nil
		},
	}

	collector := NewAccessAnalyzerCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.True(t, status.Enabled)
	assert.Equal(t, 1, status.AnalyzerCount)
	assert.Equal(t, "ACCOUNT", status.AnalyzerType)
}

func TestAccessAnalyzerCollector_Disabled(t *testing.T) {
	mock := &MockAccessAnalyzerClient{
		ListAnalyzersFunc: func(ctx context.Context, params *accessanalyzer.ListAnalyzersInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
			return &accessanalyzer.ListAnalyzersOutput{
				Analyzers: []aatypes.AnalyzerSummary{},
			}, nil
		},
	}

	collector := NewAccessAnalyzerCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.False(t, status.Enabled)
	assert.Equal(t, 0, status.AnalyzerCount)
}

func TestAccessAnalyzerCollector_Error_FailSafe(t *testing.T) {
	mock := &MockAccessAnalyzerClient{
		ListAnalyzersFunc: func(ctx context.Context, params *accessanalyzer.ListAnalyzersInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewAccessAnalyzerCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.False(t, status.Enabled)
}

func TestAccessAnalyzerStatus_ToEvidence(t *testing.T) {
	status := &AccessAnalyzerStatus{Enabled: true, AnalyzerCount: 1, Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:accessanalyzer:status", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
