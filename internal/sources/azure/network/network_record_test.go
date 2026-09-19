//go:build record

package network

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// network_record_test.go records testdata/cassettes/network.yaml against the real
// Azure Network API (NSGs + VNets, one cassette). See azuretest.RecordLiveOptions:
//
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordNetwork ./internal/sources/azure/network/ -v
func TestRecordNetwork(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential(t.Context(), azcommon.ScopeARM)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealNetwork(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/network"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeFirewallRule, EvidenceTypeNetwork}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed an NSG + VNet before recording")
	}
	t.Logf("recorded %d firewall_rule/network record(s)", len(recs))
}
