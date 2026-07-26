//go:build record

package backup

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// backup_record_test.go records testdata/cassettes/plans.yaml against the real
// Recovery Services + Backup APIs (two clients, one cassette). See
// azuretest.RecordLiveOptions:
//
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordBackup ./internal/sources/azure/backup/ -v
func TestRecordBackup(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential()
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealBackup(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/plans"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a Recovery Services vault + backup policy")
	}
	t.Logf("recorded %d backup_plan record(s)", len(recs))
}
