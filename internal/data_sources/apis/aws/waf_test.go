package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockWAFClient struct {
	ListWebACLsFunc             func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error)
	ListResourcesForWebACLFunc  func(ctx context.Context, params *wafv2.ListResourcesForWebACLInput, optFns ...func(*wafv2.Options)) (*wafv2.ListResourcesForWebACLOutput, error)
	GetWebACLFunc               func(ctx context.Context, params *wafv2.GetWebACLInput, optFns ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error)
	GetLoggingConfigurationFunc func(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error)
}

func (m *MockWAFClient) ListWebACLs(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
	return m.ListWebACLsFunc(ctx, params, optFns...)
}

func (m *MockWAFClient) ListResourcesForWebACL(ctx context.Context, params *wafv2.ListResourcesForWebACLInput, optFns ...func(*wafv2.Options)) (*wafv2.ListResourcesForWebACLOutput, error) {
	if m.ListResourcesForWebACLFunc != nil {
		return m.ListResourcesForWebACLFunc(ctx, params, optFns...)
	}
	return &wafv2.ListResourcesForWebACLOutput{}, nil
}

func (m *MockWAFClient) GetWebACL(ctx context.Context, params *wafv2.GetWebACLInput, optFns ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error) {
	if m.GetWebACLFunc != nil {
		return m.GetWebACLFunc(ctx, params, optFns...)
	}
	return &wafv2.GetWebACLOutput{}, nil
}

func (m *MockWAFClient) GetLoggingConfiguration(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error) {
	if m.GetLoggingConfigurationFunc != nil {
		return m.GetLoggingConfigurationFunc(ctx, params, optFns...)
	}
	return nil, errors.New("no logging configuration")
}

func TestWAFCollector_CollectStatus(t *testing.T) {
	tests := []struct {
		name      string
		acls      []waftypes.WebACLSummary
		resources []string
		err       error
		wantCount int
		wantALB   bool
	}{
		{
			name: "WAF with ALB protection",
			acls: []waftypes.WebACLSummary{
				{Name: awssdk.String("my-acl"), ARN: awssdk.String("arn:aws:wafv2:us-east-1:123:regional/webacl/my-acl")},
			},
			resources: []string{"arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb"},
			wantCount: 1,
			wantALB:   true,
		},
		{
			name:      "no WAF ACLs",
			acls:      []waftypes.WebACLSummary{},
			wantCount: 0,
		},
		{
			name:      "API error (fail-safe)",
			err:       errors.New("access denied"),
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockWAFClient{
				ListWebACLsFunc: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
					if tt.err != nil {
						return nil, tt.err
					}
					return &wafv2.ListWebACLsOutput{WebACLs: tt.acls}, nil
				},
				ListResourcesForWebACLFunc: func(ctx context.Context, params *wafv2.ListResourcesForWebACLInput, optFns ...func(*wafv2.Options)) (*wafv2.ListResourcesForWebACLOutput, error) {
					return &wafv2.ListResourcesForWebACLOutput{ResourceArns: tt.resources}, nil
				},
			}

			collector := NewWAFCollector(mock, "us-east-1")
			status, err := collector.CollectStatus(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tt.wantCount, status.WebACLCount)
			assert.Equal(t, tt.wantALB, status.HasALBProtection)
		})
	}
}

func TestWAFStatus_ToEvidence(t *testing.T) {
	status := &WAFStatus{WebACLCount: 1, Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:wafv2:status", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
