//go:build record

package policy

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
)

// policy_record_test.go records testdata/cassettes/assignments.yaml against the
// real Azure Policy API. Maintainer path (see azuretest.RecordLiveOptions):
//
//	az login && az account set --subscription <sub>
//	# seed: a policy assignment on the subscription
//	rm -f internal/sources/azure/policy/testdata/cassettes/assignments.yaml
//	AZURE_TEST_SUBSCRIPTION=<sub> go test -tags record -run TestRecordPolicy ./internal/sources/azure/policy/ -v
func TestRecordPolicy(t *testing.T) {
	sub := os.Getenv("AZURE_TEST_SUBSCRIPTION")
	if sub == "" {
		t.Skip("set AZURE_TEST_SUBSCRIPTION to record against a live subscription")
	}
	cred, err := azcommon.NewCredential()
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	adapter, err := newRealPolicy(sub, cred, azuretest.RecordLiveOptions(t, "testdata/cassettes/assignments"))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	p := New(Options{API: adapter, SubscriptionID: sub})

	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect (recording): %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("collected 0 records — seed a policy assignment before recording")
	}
	t.Logf("recorded %d config_change_tracking record(s)", len(recs))
}
