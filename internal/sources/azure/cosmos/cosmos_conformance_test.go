package cosmos

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// cosmos_conformance_test.go: azure.nosql_table L1+L2 (WU-2.12). Hand-authored:
// one Cosmos DB account — CMEK, continuous backup (PITR), private, local-auth off.
func TestAzureCosmosConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealCosmos(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/accounts"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"nosql_table.stream_enabled"},
	})
	if len(recs) != 1 {
		t.Fatalf("nosql_table records = %d, want 1", len(recs))
	}
	var p accountPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.EncryptionEnabled || !p.PointInTimeRecoveryEnabled {
		t.Errorf("account = %+v; want encrypted + PITR", p)
	}
}
