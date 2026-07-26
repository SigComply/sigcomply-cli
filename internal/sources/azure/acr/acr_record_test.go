//go:build record

package acr

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// acr_record_test.go records testdata/cassettes/registries.yaml against the real
// Azure Container Registry API. See azuretest.RecordLiveOptions:
//
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordACR ./internal/sources/azure/acr/ -v
func TestRecordACR(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential()
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealACR(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/registries"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a container registry before recording")
	}
	t.Logf("recorded %d container_registry record(s)", len(recs))
}
