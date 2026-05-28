package soc2

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
)

// CloudWatch alarm rule IDs. Each checks that at least one
// cloudwatch_alarm record carries a metric filter pattern matching the
// event class. Substring matching is why these use the rule: escape
// hatch — the pass_when DSL has no "contains" operator.
const (
	ruleAlarmUnauthorized = "rules.soc2.alarm_unauthorized_api_calls.v1"
	ruleAlarmRootUsage    = "rules.soc2.alarm_root_account_usage.v1"
	ruleAlarmIAMChanges   = "rules.soc2.alarm_iam_policy_changes.v1"
	ruleAlarmTrailChanges = "rules.soc2.alarm_cloudtrail_config_changes.v1"
	ruleAlarmConsoleNoMFA = "rules.soc2.alarm_console_login_no_mfa.v1"
	ruleAlarmSGChanges    = "rules.soc2.alarm_security_group_changes.v1"
	ruleAlarmVPCChanges   = "rules.soc2.alarm_vpc_changes.v1"
	ruleAlarmKMSDeletion  = "rules.soc2.alarm_kms_key_deletion.v1"
)

// alarmRules returns the CloudWatch-alarm escape-hatch rules.
func alarmRules() []core.Rule {
	return []core.Rule{
		alarmAnyContains(ruleAlarmUnauthorized, "unauthorized API calls", "Unauthorized"),
		alarmAnyContains(ruleAlarmRootUsage, "root account usage", "RootAccount", "userIdentity.type"),
		alarmAnyContains(ruleAlarmIAMChanges, "IAM policy changes", "DeleteGroupPolicy", "PutGroupPolicy", "AttachUserPolicy", "DetachUserPolicy"),
		alarmAnyContains(ruleAlarmTrailChanges, "audit log configuration changes", "StopLogging", "DeleteTrail", "UpdateTrail"),
		alarmAllContains(ruleAlarmConsoleNoMFA, "console sign-in without MFA", "ConsoleLogin", "MFAUsed"),
		alarmAnyContains(ruleAlarmSGChanges, "security group changes", "CreateSecurityGroup", "DeleteSecurityGroup", "AuthorizeSecurityGroup"),
		alarmAnyContains(ruleAlarmVPCChanges, "VPC changes", "CreateVpc", "DeleteVpc", "ModifyVpc"),
		alarmAnyContains(ruleAlarmKMSDeletion, "KMS key disable/deletion", "DisableKey", "ScheduleKeyDeletion"),
	}
}

// alarmAnyContains builds a rule that passes iff at least one alarm
// record's metric_filter_pattern contains ANY of the substrings.
func alarmAnyContains(ruleID, label string, substrings ...string) core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleID,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			for i := range in.Slots[slotName] {
				pattern := alarmPattern(in.Slots[slotName][i].Payload)
				for _, sub := range substrings {
					if strings.Contains(pattern, sub) {
						return core.RuleResult{Status: core.StatusPass}, nil
					}
				}
			}
			return core.RuleResult{
				Status:     core.StatusFail,
				Violations: []core.Violation{{ResourceID: "account", Reason: "no CloudWatch alarm covers " + label}},
			}, nil
		},
	}
}

// alarmAllContains builds a rule that passes iff at least one alarm
// record's metric_filter_pattern contains ALL of the substrings.
func alarmAllContains(ruleID, label string, substrings ...string) core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleID,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			for i := range in.Slots[slotName] {
				pattern := alarmPattern(in.Slots[slotName][i].Payload)
				if containsAll(pattern, substrings) {
					return core.RuleResult{Status: core.StatusPass}, nil
				}
			}
			return core.RuleResult{
				Status:     core.StatusFail,
				Violations: []core.Violation{{ResourceID: "account", Reason: "no CloudWatch alarm covers " + label}},
			}, nil
		},
	}
}

func containsAll(s string, subs []string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// alarmPattern extracts metric_filter_pattern from a cloudwatch_alarm payload.
func alarmPattern(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var m struct {
		Pattern string `json:"metric_filter_pattern"`
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		return ""
	}
	return m.Pattern
}
