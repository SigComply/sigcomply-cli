package storage

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	gcs "cloud.google.com/go/storage"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// storage_conformance_test.go: gcp.object_storage_bucket L1+L2 (WU-2.7).
// Hand-authored: one bucket with uniform bucket-level access + public-access
// prevention enforced, versioning, and a CMEK key.
func TestGCPStorageConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client, err := gcs.NewClient(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/buckets", "https://storage.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realGCS{client: client}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"object_storage_bucket.region_or_location", "object_storage_bucket.kms_managed", "object_storage_bucket.kms_key_id", "object_storage_bucket.versioning_enabled", "object_storage_bucket.created_at"},
	})
	if len(recs) != 1 {
		t.Fatalf("object_storage_bucket records = %d, want 1", len(recs))
	}
	var p bucketPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.PublicAccessBlocked || !p.VersioningEnabled || !p.KMSManaged {
		t.Errorf("bucket = %+v; want public-access-blocked, versioned, CMEK", p)
	}
}
