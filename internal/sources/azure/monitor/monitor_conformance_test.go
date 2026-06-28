package monitor

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// monitor_conformance_test.go: azure log_group + audit_log_trail L1+L2 (WU-2.12).
// Hand-authored: a Log Analytics workspace (90-day retention) + a subscription
// activity-log diagnostic setting exporting Administrative + Audit categories.
func TestAzureMonitorConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealMonitor(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/monitor"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	types := sourcetest.BuiltinEvidenceTypes(t)
	logs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeLogGroup}},
		EvidenceTypes: types, OptionalFields: []string{"log_group.kms_encrypted"},
	})
	trails := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeAuditLogTrail}},
		EvidenceTypes: types,
	})
	if len(logs) != 1 || len(trails) != 1 {
		t.Fatalf("records: logs=%d trails=%d, want 1/1", len(logs), len(trails))
	}
	var lg logGroupPayload
	if err := json.Unmarshal(logs[0].Payload, &lg); err != nil {
		t.Fatal(err)
	}
	if !lg.RetentionSet {
		t.Errorf("log_group = %+v; want retention set", lg)
	}
}
