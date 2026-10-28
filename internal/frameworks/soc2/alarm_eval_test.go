package soc2_test

import (
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
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
