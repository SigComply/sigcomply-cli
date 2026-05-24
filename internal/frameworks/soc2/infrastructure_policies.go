package soc2

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
)

// Infrastructure-source policy IDs. These four policies demonstrate the
// cloudtrail, cloudwatch, guardduty, and config (configservice) source
// plugins under their natural SOC 2 controls (CC7.1 monitoring +
// CC7.2 system operations / log capture).
const (
	PolicyCloudTrailMultiRegionEnabled = "soc2.cc7.2.cloudtrail_multiregion_enabled"
	PolicyCloudWatchLogsRetentionSet   = "soc2.cc7.2.cloudwatch_logs_retention_set"
	PolicyGuardDutyEnabled             = "soc2.cc7.1.guardduty_enabled"
	PolicyConfigRecorderEnabled        = "soc2.cc7.1.config_recorder_enabled"
)

// Rule IDs registered for the infrastructure-source policies.
const (
	ruleIDCloudTrailMultiRegionEnabled = "rules.soc2.cloudtrail_multiregion_enabled.v1"
	ruleIDCloudWatchLogsRetentionSet   = "rules.soc2.cloudwatch_logs_retention_set.v1"
	ruleIDGuardDutyEnabled             = "rules.soc2.guardduty_enabled.v1"
	ruleIDConfigRecorderEnabled        = "rules.soc2.config_recorder_enabled.v1"
)

// minCloudWatchRetentionDays is the threshold the CC7.2 retention
// policy enforces. 90 days mirrors the SOC 2 audit-log retention
// guidance most auditors expect.
const minCloudWatchRetentionDays = 90

// infrastructurePolicies returns the four representative policies that
// exercise the cloudtrail, cloudwatch, guardduty and config source
// plugins.
func infrastructurePolicies() []core.Policy {
	return []core.Policy{
		{
			ID:          PolicyCloudTrailMultiRegionEnabled,
			Control:     "SOC2.CC7.2",
			Description: "Every CloudTrail trail is multi-region and actively logging.",
			Remediation: "For each affected trail, set IsMultiRegionTrail=true via `aws cloudtrail update-trail --is-multi-region-trail` and ensure logging is started via `aws cloudtrail start-logging`.",
			Severity:    core.SeverityHigh,
			Category:    "logging",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"trails": {Type: "cloudtrail_trail", Cardinality: core.SlotExactlyOne, Required: true, Description: "CloudTrail trails in the account"},
			},
			RuleRef: ruleIDCloudTrailMultiRegionEnabled,
		},
		{
			ID:          PolicyCloudWatchLogsRetentionSet,
			Control:     "SOC2.CC7.2",
			Description: "Every CloudWatch log group retains logs for at least 90 days.",
			Remediation: "Set a retention policy on each affected log group via `aws logs put-retention-policy --log-group-name <name> --retention-in-days 90` (or higher).",
			Severity:    core.SeverityMedium,
			Category:    "logging",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"log_groups": {Type: "cloudwatch_log_group", Cardinality: core.SlotExactlyOne, Required: true, Description: "CloudWatch log groups"},
			},
			RuleRef: ruleIDCloudWatchLogsRetentionSet,
		},
		{
			ID:          PolicyGuardDutyEnabled,
			Control:     "SOC2.CC7.1",
			Description: "At least one GuardDuty detector is in the ENABLED state.",
			Remediation: "Enable GuardDuty in the account via the AWS Console (GuardDuty → Get started) or `aws guardduty create-detector --enable`.",
			Severity:    core.SeverityHigh,
			Category:    "monitoring",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"detectors": {Type: "guardduty_detector", Cardinality: core.SlotExactlyOne, Required: true, Description: "GuardDuty detectors"},
			},
			RuleRef: ruleIDGuardDutyEnabled,
		},
		{
			ID:          PolicyConfigRecorderEnabled,
			Control:     "SOC2.CC7.1",
			Description: "At least one AWS Config configuration recorder is recording.",
			Remediation: "Enable an AWS Config recorder via the AWS Console (Config → Settings) or `aws configservice start-configuration-recorder --configuration-recorder-name <name>`.",
			Severity:    core.SeverityHigh,
			Category:    "monitoring",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"recorders": {Type: "config_recorder", Cardinality: core.SlotExactlyOne, Required: true, Description: "AWS Config configuration recorders"},
			},
			RuleRef: ruleIDConfigRecorderEnabled,
		},
	}
}

// infrastructureRules returns the rules backing the four
// infrastructure-source policies.
func infrastructureRules() []core.Rule {
	return []core.Rule{
		cloudtrailMultiRegionEnabledRule(),
		cloudwatchLogsRetentionSetRule(),
		guardDutyEnabledRule(),
		configRecorderEnabledRule(),
	}
}

// cloudtrailMultiRegionEnabledRule fails when any trail is not
// multi-region OR is not currently logging.
func cloudtrailMultiRegionEnabledRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDCloudTrailMultiRegionEnabled,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["trails"]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				multi, err := payloadBool(r.Payload, "is_multi_region_trail")
				if err != nil {
					return core.RuleResult{}, err
				}
				logging, err := payloadBool(r.Payload, "is_logging")
				if err != nil {
					return core.RuleResult{}, err
				}
				if multi && logging {
					continue
				}
				name, err := payloadString(r.Payload, "name")
				if err != nil {
					return core.RuleResult{}, err
				}
				if name == "" {
					name = r.ID
				}
				reason := "trail " + name
				switch {
				case !multi && !logging:
					reason += " is single-region and not logging"
				case !multi:
					reason += " is single-region"
				default:
					reason += " is not logging"
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     reason,
				})
			}
			status := core.StatusPass
			if len(violations) > 0 {
				status = core.StatusFail
			}
			return core.RuleResult{Status: status, Violations: violations}, nil
		},
	}
}

// cloudwatchLogsRetentionSetRule fails when any log group has unset or
// <minCloudWatchRetentionDays retention.
func cloudwatchLogsRetentionSetRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDCloudWatchLogsRetentionSet,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["log_groups"]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				set, err := payloadBool(r.Payload, "retention_set")
				if err != nil {
					return core.RuleResult{}, err
				}
				days, err := payloadInt(r.Payload, "retention_in_days")
				if err != nil {
					return core.RuleResult{}, err
				}
				name, err := payloadString(r.Payload, "name")
				if err != nil {
					return core.RuleResult{}, err
				}
				if name == "" {
					name = r.ID
				}
				if !set {
					violations = append(violations, core.Violation{
						ResourceID: r.ID,
						Reason:     "log group " + name + " has no retention configured (logs retained indefinitely or undefined)",
					})
					continue
				}
				if days < minCloudWatchRetentionDays {
					violations = append(violations, core.Violation{
						ResourceID: r.ID,
						Reason:     "log group " + name + " retention below threshold",
					})
				}
			}
			status := core.StatusPass
			if len(violations) > 0 {
				status = core.StatusFail
			}
			return core.RuleResult{Status: status, Violations: violations}, nil
		},
	}
}

// guardDutyEnabledRule fails when no detector is in the ENABLED state.
// The rule treats GuardDuty as an account-level capability: a single
// enabled detector satisfies it. Per the architecture, the violation
// list is empty on pass and carries a single account-level marker on
// fail (no per-resource fan-out — the absence is the resource).
func guardDutyEnabledRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDGuardDutyEnabled,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["detectors"]
			for i := range records {
				r := &records[i]
				enabled, err := payloadBool(r.Payload, "enabled")
				if err != nil {
					return core.RuleResult{}, err
				}
				if enabled {
					return core.RuleResult{Status: core.StatusPass, Violations: []core.Violation{}}, nil
				}
			}
			return core.RuleResult{
				Status: core.StatusFail,
				Violations: []core.Violation{{
					ResourceID: "account",
					Reason:     "GuardDuty is not enabled in this account (no detector in ENABLED state)",
				}},
			}, nil
		},
	}
}

// configRecorderEnabledRule fails when no AWS Config recorder is
// recording. Same account-level shape as guardDutyEnabledRule.
func configRecorderEnabledRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDConfigRecorderEnabled,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["recorders"]
			for i := range records {
				r := &records[i]
				rec, err := payloadBool(r.Payload, "recording")
				if err != nil {
					return core.RuleResult{}, err
				}
				if rec {
					return core.RuleResult{Status: core.StatusPass, Violations: []core.Violation{}}, nil
				}
			}
			return core.RuleResult{
				Status: core.StatusFail,
				Violations: []core.Violation{{
					ResourceID: "account",
					Reason:     "AWS Config is not recording in this account (no recorder in the recording state)",
				}},
			}, nil
		},
	}
}
