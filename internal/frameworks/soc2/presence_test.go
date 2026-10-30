package soc2

import (
	"slices"
	"testing"
)

// TestPresencePolicies pins which policies fail, rather than skip, when
// their bound source returns no records. Each asks whether a service
// exists at all, so "nothing found" is the gap itself. Adding or removing
// one changes verdicts on real estates; do it deliberately.
func TestPresencePolicies(t *testing.T) {
	want := []string{
		"soc2.a1.2.backup_plan_exists",
		"soc2.cc6.1.password_min_length_14", // gitleaks:allow -- a policy ID, not a key
		"soc2.cc6.8.macie_enabled",
		"soc2.cc6.8.threat_detection_enabled",
		"soc2.cc7.1.audit_logging_enabled",
		"soc2.cc7.1.config_recording_enabled",
		"soc2.cc7.1.inspector_enabled",
		"soc2.cc7.1.securityhub_enabled",
		"soc2.cc7.2.alarm_cloudtrail_config_changes",
		"soc2.cc7.2.alarm_console_login_no_mfa",
		"soc2.cc7.2.alarm_iam_policy_changes",
		"soc2.cc7.2.alarm_kms_key_deletion",
		"soc2.cc7.2.alarm_root_account_usage",
		"soc2.cc7.2.alarm_security_group_changes",
		"soc2.cc7.2.alarm_unauthorized_api_calls",
		"soc2.cc7.2.alarm_vpc_changes",
	}
	var got []string
	for _, p := range Policies() {
		for _, s := range p.Slots {
			if s.FailWhenEmpty {
				got = append(got, p.ID)
				break
			}
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("presence policies = %v\nwant %v", got, want)
	}
}
