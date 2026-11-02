package soc2_test

import (
	"context"
	"encoding/json"
	"testing"

	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/securityalert"
)

// An alarm that notifies no one is not an alert: the CC7.2 alarm
// policies need an enabled alert with a notification target, and a
// record that does not say whether anyone is notified does not pass.
func TestAlarmPolicies_RequireNotificationTarget(t *testing.T) {
	const id = "soc2.cc7.2.alarm_root_account_usage"
	alert := func(extra map[string]any) core.EvidenceRecord {
		p := map[string]any{"id": "a1", "name": "root", "event_class": "root_account_usage", "is_enabled": true}
		for k, v := range extra {
			p[k] = v
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return core.EvidenceRecord{ID: "a1", Type: "security_alert", SourceID: "aws.security_alert", Payload: b}
	}
	for name, tc := range map[string]struct {
		extra map[string]any
		want  core.PolicyStatus
	}{
		"notifies a target":    {map[string]any{"has_notification_target": true}, core.StatusPass},
		"notifies no one":      {map[string]any{"has_notification_target": false}, core.StatusFail},
		"target not disclosed": {nil, core.StatusFail},
	} {
		t.Run(name, func(t *testing.T) {
			got := evalPolicy(t, id, map[string][]core.EvidenceRecord{slotEvidence: {alert(tc.extra)}})
			if got.Status != tc.want {
				t.Errorf("status = %q (%v); want %q", got.Status, got.Diag, tc.want)
			}
		})
	}
}

type alarmAPI struct {
	filters []cwltypes.MetricFilter
	alarms  []cwtypes.MetricAlarm
}

func (f *alarmAPI) DescribeMetricFilters(context.Context, *cwl.DescribeMetricFiltersInput, ...func(*cwl.Options)) (*cwl.DescribeMetricFiltersOutput, error) {
	return &cwl.DescribeMetricFiltersOutput{MetricFilters: f.filters}, nil
}

func (f *alarmAPI) DescribeAlarms(context.Context, *cw.DescribeAlarmsInput, ...func(*cw.Options)) (*cw.DescribeAlarmsOutput, error) {
	return &cw.DescribeAlarmsOutput{MetricAlarms: f.alarms}, nil
}

// The CIS console-sign-in-without-MFA filter also tests
// $.userIdentity.type = "IAMUser". From aws.security_alert through the
// shipped policies, it must satisfy the console policy and not the root-usage
// one when no root alarm exists.
func TestAlarmPolicies_CISConsoleNoMFAAlarmIsNotRootUsage(t *testing.T) {
	str := func(s string) *string { return &s }
	api := &alarmAPI{
		filters: []cwltypes.MetricFilter{{
			FilterName:            str("console-signin-no-mfa"),
			FilterPattern:         str(`{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }`),
			MetricTransformations: []cwltypes.MetricTransformation{{MetricName: str("ConsoleSigninNoMFA"), MetricNamespace: str("CISBenchmark")}},
		}},
		alarms: []cwtypes.MetricAlarm{{
			AlarmName:    str("console-signin-no-mfa"),
			MetricName:   str("ConsoleSigninNoMFA"),
			Namespace:    str("CISBenchmark"),
			AlarmActions: []string{"arn:aws:sns:us-east-1:111122223333:secops"},
		}},
	}
	p := securityalert.New(securityalert.Options{API: api})
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{securityalert.EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	slot := map[string][]core.EvidenceRecord{slotEvidence: recs}

	if got := evalPolicy(t, "soc2.cc7.2.alarm_root_account_usage", slot); got.Status != core.StatusFail {
		t.Errorf("alarm_root_account_usage = %q; want %q (no root-usage alarm is configured)", got.Status, core.StatusFail)
	}
	if got := evalPolicy(t, "soc2.cc7.2.alarm_console_login_no_mfa", slot); got.Status != core.StatusPass {
		t.Errorf("alarm_console_login_no_mfa = %q; want %q", got.Status, core.StatusPass)
	}
}
