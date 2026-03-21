package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// EventBridgeClient defines the interface for EventBridge operations.
type EventBridgeClient interface {
	ListRules(ctx context.Context, params *eventbridge.ListRulesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error)
	ListTargetsByRule(ctx context.Context, params *eventbridge.ListTargetsByRuleInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListTargetsByRuleOutput, error)
}

// GuardDutyAlertStatus represents EventBridge alerting for GuardDuty findings.
type GuardDutyAlertStatus struct {
	HasGuardDutyRule bool     `json:"has_guardduty_rule"`
	RuleCount        int      `json:"rule_count"`
	TargetTypes      []string `json:"target_types,omitempty"`
	Region           string   `json:"region"`
}

// ToEvidence converts a GuardDutyAlertStatus to Evidence.
func (s *GuardDutyAlertStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:events:%s:%s:guardduty-alert", s.Region, accountID)
	ev := evidence.New("aws", "aws:eventbridge:guardduty-alert", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EventBridgeCollector collects EventBridge status.
type EventBridgeCollector struct {
	client EventBridgeClient
	region string
}

// NewEventBridgeCollector creates a new EventBridge collector.
func NewEventBridgeCollector(client EventBridgeClient, region string) *EventBridgeCollector {
	return &EventBridgeCollector{client: client, region: region}
}

// CollectGuardDutyAlerts checks for EventBridge rules that capture GuardDuty findings.
func (c *EventBridgeCollector) CollectGuardDutyAlerts(ctx context.Context) (*GuardDutyAlertStatus, error) {
	status := &GuardDutyAlertStatus{Region: c.region}

	output, err := c.client.ListRules(ctx, &eventbridge.ListRulesInput{})
	if err != nil {
		return status, nil
	}

	for _, rule := range output.Rules {
		pattern := awssdk.ToString(rule.EventPattern)
		if strings.Contains(pattern, "aws.guardduty") || strings.Contains(pattern, "GuardDuty Finding") {
			status.HasGuardDutyRule = true
			status.RuleCount++

			// Get targets for this rule
			targets, err := c.client.ListTargetsByRule(ctx, &eventbridge.ListTargetsByRuleInput{
				Rule: rule.Name,
			})
			if err == nil {
				for _, target := range targets.Targets {
					arn := awssdk.ToString(target.Arn)
					if strings.Contains(arn, ":sns:") {
						status.TargetTypes = appendUnique(status.TargetTypes, "SNS")
					} else if strings.Contains(arn, ":lambda:") {
						status.TargetTypes = appendUnique(status.TargetTypes, "Lambda")
					} else if strings.Contains(arn, ":sqs:") {
						status.TargetTypes = appendUnique(status.TargetTypes, "SQS")
					}
				}
			}
		}
	}

	return status, nil
}

// appendUnique appends a value to a slice if it doesn't already exist.
func appendUnique(slice []string, value string) []string {
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

// CollectEvidence collects EventBridge GuardDuty alert status as evidence.
func (c *EventBridgeCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectGuardDutyAlerts(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
