package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockEventBridgeClient struct {
	ListRulesFunc          func(ctx context.Context, params *eventbridge.ListRulesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error)
	ListTargetsByRuleFunc  func(ctx context.Context, params *eventbridge.ListTargetsByRuleInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListTargetsByRuleOutput, error)
}

func (m *MockEventBridgeClient) ListRules(ctx context.Context, params *eventbridge.ListRulesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error) {
	return m.ListRulesFunc(ctx, params, optFns...)
}

func (m *MockEventBridgeClient) ListTargetsByRule(ctx context.Context, params *eventbridge.ListTargetsByRuleInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListTargetsByRuleOutput, error) {
	if m.ListTargetsByRuleFunc != nil {
		return m.ListTargetsByRuleFunc(ctx, params, optFns...)
	}
	return &eventbridge.ListTargetsByRuleOutput{}, nil
}

func TestEventBridgeCollector_HasGuardDutyRule(t *testing.T) {
	mock := &MockEventBridgeClient{
		ListRulesFunc: func(ctx context.Context, params *eventbridge.ListRulesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error) {
			return &eventbridge.ListRulesOutput{
				Rules: []ebtypes.Rule{
					{
						Name:         awssdk.String("guardduty-alerts"),
						EventPattern: awssdk.String(`{"source": ["aws.guardduty"]}`),
					},
				},
			}, nil
		},
		ListTargetsByRuleFunc: func(ctx context.Context, params *eventbridge.ListTargetsByRuleInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListTargetsByRuleOutput, error) {
			return &eventbridge.ListTargetsByRuleOutput{
				Targets: []ebtypes.Target{
					{Arn: awssdk.String("arn:aws:sns:us-east-1:123:guardduty-alerts")},
				},
			}, nil
		},
	}

	collector := NewEventBridgeCollector(mock, "us-east-1")
	status, err := collector.CollectGuardDutyAlerts(context.Background())

	require.NoError(t, err)
	assert.True(t, status.HasGuardDutyRule)
	assert.Equal(t, 1, status.RuleCount)
	assert.Contains(t, status.TargetTypes, "SNS")
}

func TestEventBridgeCollector_NoGuardDutyRule(t *testing.T) {
	mock := &MockEventBridgeClient{
		ListRulesFunc: func(ctx context.Context, params *eventbridge.ListRulesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error) {
			return &eventbridge.ListRulesOutput{
				Rules: []ebtypes.Rule{
					{
						Name:         awssdk.String("other-rule"),
						EventPattern: awssdk.String(`{"source": ["aws.ec2"]}`),
					},
				},
			}, nil
		},
	}

	collector := NewEventBridgeCollector(mock, "us-east-1")
	status, err := collector.CollectGuardDutyAlerts(context.Background())

	require.NoError(t, err)
	assert.False(t, status.HasGuardDutyRule)
	assert.Equal(t, 0, status.RuleCount)
}

func TestEventBridgeCollector_Error_FailSafe(t *testing.T) {
	mock := &MockEventBridgeClient{
		ListRulesFunc: func(ctx context.Context, params *eventbridge.ListRulesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEventBridgeCollector(mock, "us-east-1")
	status, err := collector.CollectGuardDutyAlerts(context.Background())

	require.NoError(t, err)
	assert.False(t, status.HasGuardDutyRule)
}

func TestGuardDutyAlertStatus_ToEvidence(t *testing.T) {
	status := &GuardDutyAlertStatus{HasGuardDutyRule: true, Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:eventbridge:guardduty-alert", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
