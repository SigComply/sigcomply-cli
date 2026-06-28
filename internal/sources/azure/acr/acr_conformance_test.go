package acr

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// acr_conformance_test.go: azure.container_registry L1+L2 (WU-2.12). Hand-authored:
// a Premium registry — private (no anon pull, public network disabled), CMEK,
// quarantine policy on.
func TestAzureACRConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealACR(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/registries"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"container_registry.image_immutability_enabled"},
	})
	if len(recs) != 1 {
		t.Fatalf("container_registry records = %d, want 1", len(recs))
	}
	var p registryPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.IsPublic || !p.EncryptionEnabled {
		t.Errorf("registry = %+v; want private + encrypted", p)
	}
}
