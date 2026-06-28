package securityalert

import (
	"encoding/json"
	"testing"
	"time"

	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// securityalert_conformance_test.go: aws.security_alert L1+L2 (WU-2.6).
// Multi-service plugin (CloudWatch Logs metric filters + CloudWatch alarms).
// Recorded against provisioned metric filters wired to alarms (root-account
// usage + unauthorized API calls), both with an SNS notification target.
func TestSecurityAlertConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		cfg := awstest.ReplayConfig(t, "testdata/cassettes/alerts")
		api := &awsAPI{logs: cwl.NewFromConfig(cfg), alarms: cw.NewFromConfig(cfg)}
		return New(Options{API: api, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) < 2 {
		t.Fatalf("security_alert records = %d, want >= 2", len(recs))
	}
	classes := map[string]bool{}
	for _, r := range recs {
		var p securityAlertPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		classes[p.EventClass] = true
		if !p.IsEnabled || !p.HasNotificationTarget {
			t.Errorf("alert %q = %+v; want enabled with a notification target", p.ID, p)
		}
	}
	for _, want := range []string{"root_account_usage", "unauthorized_api_calls"} {
		if !classes[want] {
			t.Errorf("missing event_class %q (got %v)", want, classes)
		}
	}
}
