package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSTSClient is a mock implementation of STSClient for testing.
type MockSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *MockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.GetCallerIdentityFunc(ctx, params, optFns...)
}

func TestCollector_GetAccountID(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *sts.GetCallerIdentityOutput
		mockError     error
		wantAccountID string
		wantError     bool
	}{
		{
			name: "successful account ID retrieval",
			mockResponse: &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
				UserId:  aws.String("AIDAEXAMPLEID"),
			},
			wantAccountID: "123456789012",
			wantError:     false,
		},
		{
			name:      "STS API error",
			mockError: errors.New("access denied"),
			wantError: true,
		},
		{
			name: "nil account in response",
			mockResponse: &sts.GetCallerIdentityOutput{
				Account: nil,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSTS := &MockSTSClient{
				GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			collector := &Collector{
				stsClient: mockSTS,
			}

			accountID, err := collector.GetAccountID(context.Background())

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantAccountID, accountID)
			}
		})
	}
}

func TestCollector_New(t *testing.T) {
	// This test verifies the constructor doesn't panic
	// Actual AWS credential loading is tested in integration tests
	collector := New()
	assert.NotNil(t, collector)
}

func TestCollector_WithRegion(t *testing.T) {
	collector := New()

	// Chain method should return the collector
	result := collector.WithRegion("us-west-2")
	assert.Equal(t, collector, result)
	assert.Equal(t, "us-west-2", collector.region)
}

func TestCollector_Status(t *testing.T) {
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
			}, nil
		},
	}

	collector := &Collector{
		stsClient: mockSTS,
		region:    "us-east-1",
	}

	status := collector.Status(context.Background())

	assert.True(t, status.Connected)
	assert.Equal(t, "123456789012", status.AccountID)
	assert.Equal(t, "us-east-1", status.Region)
}

func TestCollector_Status_NotConnected(t *testing.T) {
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return nil, errors.New("no credentials")
		},
	}

	collector := &Collector{
		stsClient: mockSTS,
	}

	status := collector.Status(context.Background())

	assert.False(t, status.Connected)
	assert.Contains(t, status.Error, "no credentials")
}
