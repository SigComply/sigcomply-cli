package keyvault

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// keyvault_conformance_test.go: azure kms_key + secret L1+L2 (WU-2.12).
// Recorded live: one key with a rotate-after-1-year policy + one secret. Run
// per type.
func TestAzureKeyvaultConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealKeyvault(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/keyvault"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	types := sourcetest.BuiltinEvidenceTypes(t)
	keys := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeKMSKey}},
		EvidenceTypes: types, OptionalFields: []string{"kms_key.arn", "kms_key.rotation_supported"},
	})
	secrets := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeSecret}},
		EvidenceTypes: types, OptionalFields: []string{"secret.last_rotated_days"},
	})
	if len(keys) != 1 || len(secrets) != 1 {
		t.Fatalf("records: keys=%d secrets=%d, want 1/1", len(keys), len(secrets))
	}
	var k keyPayload
	if err := json.Unmarshal(keys[0].Payload, &k); err != nil {
		t.Fatal(err)
	}
	// The management plane returns the action type as "Rotate", not the SDK
	// constant's "rotate".
	if !k.IsCustomerManaged || !k.Enabled || !k.RotationEnabled || k.RotationPeriod != "P1Y" {
		t.Errorf("key = %+v; want customer-managed, enabled, rotating every P1Y", k)
	}
}
