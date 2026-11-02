package policy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// policy_conformance_test.go: azure.config_change_tracking L1+L2 (WU-2.12).
// Recorded live: one customer assignment scoped at the subscription, plus the
// SystemHidden region restriction Microsoft places on the tenant root
// management group, which must not be counted.
func TestAzurePolicyConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealPolicy(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/assignments"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("config_change_tracking records = %d, want 1", len(recs))
	}
	var p trackingPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsRecording || p.AssignmentCount != 1 {
		t.Errorf("tracking = %+v; want recording from the one customer assignment", p)
	}
	if !p.AllResourceTypes || p.SubscriptionScopedCount != 1 || p.ManagementGroupScopedCount != 0 {
		t.Errorf("tracking = %+v; want full coverage from the subscription assignment alone", p)
	}
}
