//go:build record

package aks

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// aks_record_test.go records testdata/cassettes/clusters.yaml against the real
// AKS + Monitor diagnostic APIs (two clients, one cassette). See
// azuretest.RecordLiveOptions:
//
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordAKS ./internal/sources/azure/aks/ -v
func TestRecordAKS(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential()
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealAKS(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/clusters"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed an AKS cluster before recording")
	}
	t.Logf("recorded %d kubernetes_cluster record(s)", len(recs))
}
