package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3ctypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockS3ControlClient struct {
	GetPublicAccessBlockFunc func(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

func (m *MockS3ControlClient) GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	return m.GetPublicAccessBlockFunc(ctx, params, optFns...)
}

func TestS3ControlCollector_CollectAccountPublicAccess(t *testing.T) {
	tests := []struct {
		name           string
		config         *s3ctypes.PublicAccessBlockConfiguration
		err            error
		wantAllBlocked bool
	}{
		{
			name: "all blocked",
			config: &s3ctypes.PublicAccessBlockConfiguration{
				BlockPublicAcls:       awssdk.Bool(true),
				BlockPublicPolicy:     awssdk.Bool(true),
				IgnorePublicAcls:      awssdk.Bool(true),
				RestrictPublicBuckets: awssdk.Bool(true),
			},
			wantAllBlocked: true,
		},
		{
			name: "partially blocked",
			config: &s3ctypes.PublicAccessBlockConfiguration{
				BlockPublicAcls:   awssdk.Bool(true),
				BlockPublicPolicy: awssdk.Bool(false),
			},
			wantAllBlocked: false,
		},
		{
			name:           "not configured (error)",
			err:            errors.New("NoSuchPublicAccessBlockConfiguration"),
			wantAllBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockS3ControlClient{
				GetPublicAccessBlockFunc: func(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
					if tt.err != nil {
						return nil, tt.err
					}
					return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: tt.config}, nil
				},
			}

			collector := NewS3ControlCollector(mock)
			config, err := collector.CollectAccountPublicAccess(context.Background(), "123456789012")

			require.NoError(t, err)
			assert.Equal(t, tt.wantAllBlocked, config.AllBlocked)
		})
	}
}

func TestS3ControlCollector_CollectEvidence(t *testing.T) {
	mock := &MockS3ControlClient{
		GetPublicAccessBlockFunc: func(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
			return &s3control.GetPublicAccessBlockOutput{
				PublicAccessBlockConfiguration: &s3ctypes.PublicAccessBlockConfiguration{
					BlockPublicAcls: awssdk.Bool(true), BlockPublicPolicy: awssdk.Bool(true),
					IgnorePublicAcls: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
				},
			}, nil
		},
	}

	collector := NewS3ControlCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.Len(t, ev, 1)
	assert.Equal(t, "aws:s3control:account-public-access", ev[0].ResourceType)
}
