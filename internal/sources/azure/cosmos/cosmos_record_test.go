//go:build record

package cosmos

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// cosmos_record_test.go records testdata/cassettes/accounts.yaml against the real
// Azure Cosmos DB API. See azuretest.RecordLiveOptions:
//
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordCosmos ./internal/sources/azure/cosmos/ -v
func TestRecordCosmos(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential()
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealCosmos(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/accounts"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a Cosmos DB account before recording")
	}
	t.Logf("recorded %d nosql_table record(s)", len(recs))
}
