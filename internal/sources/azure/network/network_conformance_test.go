package network

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// network_conformance_test.go: azure firewall_rule + network L1+L2 (WU-2.12).
// Hand-authored: an NSG with an inbound 0.0.0.0/0 SSH allow rule + a VNet with
// flow logs enabled. Run per evidence type.
func TestAzureNetworkConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealNetwork(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/network"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	types := sourcetest.BuiltinEvidenceTypes(t)
	rules := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeFirewallRule}},
		EvidenceTypes: types, OptionalFields: []string{"firewall_rule.source_cidr", "firewall_rule.dest_cidr"},
	})
	nets := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeNetwork}},
		EvidenceTypes: types, OptionalFields: []string{"network.cidr_block"},
	})
	if len(rules) != 1 || len(nets) != 1 {
		t.Fatalf("records: rules=%d nets=%d, want 1/1", len(rules), len(nets))
	}
	var rule rulePayload
	if err := json.Unmarshal(rules[0].Payload, &rule); err != nil {
		t.Fatal(err)
	}
	var net networkPayload
	if err := json.Unmarshal(nets[0].Payload, &net); err != nil {
		t.Fatal(err)
	}
	if !rule.IsUnrestrictedIPv4 || !net.FlowLogsEnabled {
		t.Errorf("rule=%+v net=%+v; want unrestricted ingress + flow logs", rule, net)
	}
}
