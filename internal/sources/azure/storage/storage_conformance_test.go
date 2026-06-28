package storage

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// storage_conformance_test.go: azure.object_storage_bucket L1+L2 (WU-2.12). The
// subscription is empty, so the cassette is hand-authored (httptest-record via
// the azuretest seam). One account: CMEK, public blob access blocked, blob
// versioning on.
func TestAzureStorageConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealStorage(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/accounts"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"object_storage_bucket.region_or_location", "object_storage_bucket.kms_managed",
			"object_storage_bucket.kms_key_id", "object_storage_bucket.versioning_enabled",
			"object_storage_bucket.created_at",
		},
	})
	if len(recs) != 1 {
		t.Fatalf("object_storage_bucket records = %d, want 1", len(recs))
	}
	var p bucketPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.PublicAccessBlocked || !p.KMSManaged {
		t.Errorf("account = %+v; want public-access-blocked + CMEK", p)
	}
}
