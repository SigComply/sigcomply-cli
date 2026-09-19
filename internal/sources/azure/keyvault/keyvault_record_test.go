//go:build record

package keyvault

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// keyvault_record_test.go records testdata/cassettes/keyvault.yaml against the
// real Key Vault API (vaults + keys + secrets, one cassette). See
// azuretest.RecordLiveOptions:
//
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordKeyvault ./internal/sources/azure/keyvault/ -v
func TestRecordKeyvault(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential(t.Context(), azcommon.ScopeARM)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealKeyvault(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/keyvault"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeKMSKey, EvidenceTypeSecret}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a key vault with a key + secret before recording")
	}
	t.Logf("recorded %d key/secret record(s)", len(recs))
}
