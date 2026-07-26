//go:build record

package storage

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// storage_record_test.go records testdata/cassettes/accounts.yaml against the
// real Azure Storage API (see azuretest.RecordLiveOptions):
//
//	az login && az account set --subscription <sub>
//	rm -f internal/sources/azure/storage/testdata/cassettes/accounts.yaml
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordStorage ./internal/sources/azure/storage/ -v
func TestRecordStorage(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential()
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealStorage(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/accounts"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a storage account before recording")
	}
	t.Logf("recorded %d object_storage_bucket record(s)", len(recs))
}
