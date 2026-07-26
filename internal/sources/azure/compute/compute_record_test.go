//go:build record

package compute

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// compute_record_test.go records testdata/cassettes/vms.yaml against the real
// Azure Compute + Network APIs (VMs + their NICs, one cassette). The VM is
// seeded via an ARM template (scripts/setup-azure.sh full tier), since
// `az vm create` is broken on some az-CLI/Python builds. See
// azuretest.RecordLiveOptions:
//
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordCompute ./internal/sources/azure/compute/ -v
func TestRecordCompute(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential()
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealCompute(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/vms"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a running VM before recording")
	}
	t.Logf("recorded %d compute_instance record(s)", len(recs))
}
