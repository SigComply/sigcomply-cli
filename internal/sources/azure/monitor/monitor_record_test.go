//go:build record

package monitor

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// monitor_record_test.go records testdata/cassettes/monitor.yaml against the real
// Azure Monitor API (Log Analytics workspaces + subscription diagnostic
// settings, one cassette). See azuretest.RecordLiveOptions:
//
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordMonitor ./internal/sources/azure/monitor/ -v
func TestRecordMonitor(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential(t.Context(), azcommon.ScopeARM)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealMonitor(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/monitor"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeLogGroup, EvidenceTypeAuditLogTrail}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a Log Analytics workspace + diagnostic setting")
	}
	t.Logf("recorded %d log/trail record(s)", len(recs))
}
