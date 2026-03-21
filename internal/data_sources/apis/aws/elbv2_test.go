package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockELBv2Client struct {
	DescribeLoadBalancersFunc          func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error)
	DescribeListenersFunc              func(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error)
	DescribeLoadBalancerAttributesFunc func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error)
}

func (m *MockELBv2Client) DescribeLoadBalancers(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	return m.DescribeLoadBalancersFunc(ctx, params, optFns...)
}

func (m *MockELBv2Client) DescribeListeners(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	return m.DescribeListenersFunc(ctx, params, optFns...)
}

func (m *MockELBv2Client) DescribeLoadBalancerAttributes(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error) {
	if m.DescribeLoadBalancerAttributesFunc != nil {
		return m.DescribeLoadBalancerAttributesFunc(ctx, params, optFns...)
	}
	return &elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{}, nil
}

func TestELBv2Collector_HTTPSListener(t *testing.T) {
	mock := &MockELBv2Client{
		DescribeLoadBalancersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
			return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{
						LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"),
						LoadBalancerName: awssdk.String("my-alb"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
						Scheme:           elbtypes.LoadBalancerSchemeEnumInternetFacing,
					},
				},
			}, nil
		},
		DescribeListenersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
			return &elasticloadbalancingv2.DescribeListenersOutput{
				Listeners: []elbtypes.Listener{
					{
						Protocol: elbtypes.ProtocolEnumHttps,
						Port:     awssdk.Int32(443),
						DefaultActions: []elbtypes.Action{
							{Type: elbtypes.ActionTypeEnumForward},
						},
					},
				},
			}, nil
		},
	}

	collector := NewELBv2Collector(mock)
	lbs, err := collector.CollectLoadBalancers(context.Background())

	require.NoError(t, err)
	require.Len(t, lbs, 1)
	assert.True(t, lbs[0].HTTPSEnforced)
	assert.Equal(t, "my-alb", lbs[0].Name)
}

func TestELBv2Collector_HTTPOnly(t *testing.T) {
	mock := &MockELBv2Client{
		DescribeLoadBalancersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
			return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{
						LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/http-alb/def"),
						LoadBalancerName: awssdk.String("http-alb"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
						Scheme:           elbtypes.LoadBalancerSchemeEnumInternetFacing,
					},
				},
			}, nil
		},
		DescribeListenersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
			return &elasticloadbalancingv2.DescribeListenersOutput{
				Listeners: []elbtypes.Listener{
					{
						Protocol: elbtypes.ProtocolEnumHttp,
						Port:     awssdk.Int32(80),
						DefaultActions: []elbtypes.Action{
							{Type: elbtypes.ActionTypeEnumForward},
						},
					},
				},
			}, nil
		},
	}

	collector := NewELBv2Collector(mock)
	lbs, err := collector.CollectLoadBalancers(context.Background())

	require.NoError(t, err)
	require.Len(t, lbs, 1)
	assert.False(t, lbs[0].HTTPSEnforced)
}

func TestELBv2Collector_HTTPRedirectToHTTPS(t *testing.T) {
	mock := &MockELBv2Client{
		DescribeLoadBalancersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
			return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{
						LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/redirect-alb/ghi"),
						LoadBalancerName: awssdk.String("redirect-alb"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
						Scheme:           elbtypes.LoadBalancerSchemeEnumInternetFacing,
					},
				},
			}, nil
		},
		DescribeListenersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
			return &elasticloadbalancingv2.DescribeListenersOutput{
				Listeners: []elbtypes.Listener{
					{
						Protocol: elbtypes.ProtocolEnumHttp,
						Port:     awssdk.Int32(80),
						DefaultActions: []elbtypes.Action{
							{
								Type: elbtypes.ActionTypeEnumRedirect,
								RedirectConfig: &elbtypes.RedirectActionConfig{
									Protocol: awssdk.String("HTTPS"),
								},
							},
						},
					},
					{
						Protocol: elbtypes.ProtocolEnumHttps,
						Port:     awssdk.Int32(443),
						DefaultActions: []elbtypes.Action{
							{Type: elbtypes.ActionTypeEnumForward},
						},
					},
				},
			}, nil
		},
	}

	collector := NewELBv2Collector(mock)
	lbs, err := collector.CollectLoadBalancers(context.Background())

	require.NoError(t, err)
	require.Len(t, lbs, 1)
	assert.True(t, lbs[0].HTTPSEnforced)
}

func TestELBv2Collector_EmptyList(t *testing.T) {
	mock := &MockELBv2Client{
		DescribeLoadBalancersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
			return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{},
			}, nil
		},
	}

	collector := NewELBv2Collector(mock)
	lbs, err := collector.CollectLoadBalancers(context.Background())

	require.NoError(t, err)
	assert.Empty(t, lbs)
}

func TestELBv2Collector_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockELBv2Client{
		DescribeLoadBalancersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
			callCount++
			if callCount == 1 {
				return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
					LoadBalancers: []elbtypes.LoadBalancer{
						{
							LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/alb-1/abc"),
							LoadBalancerName: awssdk.String("alb-1"),
							Type:             elbtypes.LoadBalancerTypeEnumApplication,
						},
					},
					NextMarker: awssdk.String("page2"),
				}, nil
			}
			return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{
						LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/alb-2/def"),
						LoadBalancerName: awssdk.String("alb-2"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
					},
				},
			}, nil
		},
		DescribeListenersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
			return &elasticloadbalancingv2.DescribeListenersOutput{
				Listeners: []elbtypes.Listener{
					{
						Protocol: elbtypes.ProtocolEnumHttps,
						Port:     awssdk.Int32(443),
						DefaultActions: []elbtypes.Action{
							{Type: elbtypes.ActionTypeEnumForward},
						},
					},
				},
			}, nil
		},
	}

	collector := NewELBv2Collector(mock)
	lbs, err := collector.CollectLoadBalancers(context.Background())

	require.NoError(t, err)
	require.Len(t, lbs, 2)
	assert.Equal(t, "alb-1", lbs[0].Name)
	assert.Equal(t, "alb-2", lbs[1].Name)
}

func TestELBv2Collector_Error(t *testing.T) {
	mock := &MockELBv2Client{
		DescribeLoadBalancersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewELBv2Collector(mock)
	_, err := collector.CollectLoadBalancers(context.Background())
	assert.Error(t, err)
}

func TestELBv2Collector_AccessLogsEnabled(t *testing.T) {
	mock := &MockELBv2Client{
		DescribeLoadBalancersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
			return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{
						LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"),
						LoadBalancerName: awssdk.String("my-alb"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
					},
				},
			}, nil
		},
		DescribeListenersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
			return &elasticloadbalancingv2.DescribeListenersOutput{
				Listeners: []elbtypes.Listener{
					{Protocol: elbtypes.ProtocolEnumHttps, Port: awssdk.Int32(443), DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward}}},
				},
			}, nil
		},
		DescribeLoadBalancerAttributesFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error) {
			return &elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
				Attributes: []elbtypes.LoadBalancerAttribute{
					{Key: awssdk.String("access_logs.s3.enabled"), Value: awssdk.String("true")},
					{Key: awssdk.String("access_logs.s3.bucket"), Value: awssdk.String("my-log-bucket")},
				},
			}, nil
		},
	}

	collector := NewELBv2Collector(mock)
	lbs, err := collector.CollectLoadBalancers(context.Background())

	require.NoError(t, err)
	require.Len(t, lbs, 1)
	assert.True(t, lbs[0].AccessLogsEnabled)
}

func TestELBv2Collector_AccessLogsDisabled(t *testing.T) {
	mock := &MockELBv2Client{
		DescribeLoadBalancersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
			return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{
						LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"),
						LoadBalancerName: awssdk.String("my-alb"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
					},
				},
			}, nil
		},
		DescribeListenersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
			return &elasticloadbalancingv2.DescribeListenersOutput{
				Listeners: []elbtypes.Listener{
					{Protocol: elbtypes.ProtocolEnumHttps, Port: awssdk.Int32(443), DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward}}},
				},
			}, nil
		},
		DescribeLoadBalancerAttributesFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error) {
			return &elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
				Attributes: []elbtypes.LoadBalancerAttribute{
					{Key: awssdk.String("access_logs.s3.enabled"), Value: awssdk.String("false")},
				},
			}, nil
		},
	}

	collector := NewELBv2Collector(mock)
	lbs, err := collector.CollectLoadBalancers(context.Background())

	require.NoError(t, err)
	require.Len(t, lbs, 1)
	assert.False(t, lbs[0].AccessLogsEnabled)
}

func TestELBv2Collector_AccessLogsError_FailSafe(t *testing.T) {
	mock := &MockELBv2Client{
		DescribeLoadBalancersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
			return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{
						LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"),
						LoadBalancerName: awssdk.String("my-alb"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
					},
				},
			}, nil
		},
		DescribeListenersFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
			return &elasticloadbalancingv2.DescribeListenersOutput{
				Listeners: []elbtypes.Listener{
					{Protocol: elbtypes.ProtocolEnumHttps, Port: awssdk.Int32(443), DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward}}},
				},
			}, nil
		},
		DescribeLoadBalancerAttributesFunc: func(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewELBv2Collector(mock)
	lbs, err := collector.CollectLoadBalancers(context.Background())

	require.NoError(t, err, "should not fail when attributes query fails")
	require.Len(t, lbs, 1)
	assert.False(t, lbs[0].AccessLogsEnabled, "access logs should default to false on error")
}

func TestLoadBalancer_ToEvidence(t *testing.T) {
	lb := &LoadBalancer{ARN: "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc", Name: "my-alb"}
	ev := lb.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:elbv2:load-balancer", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
