package kms

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	cloudkms "google.golang.org/api/cloudkms/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// kms_conformance_test.go: gcp.kms_key L1+L2 (WU-2.11). Hand-authored: one
// customer-managed HSM key with rotation enabled (location→keyRing→cryptoKey walk).
func TestGCPKMSConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := cloudkms.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/keys", "https://cloudkms.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realKMS{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"kms_key.arn"},
	})
	if len(recs) != 1 {
		t.Fatalf("kms_key records = %d, want 1", len(recs))
	}
	var p keyPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsCustomerManaged || !p.RotationEnabled || !p.Enabled {
		t.Errorf("key = %+v; want customer-managed, rotation, enabled", p)
	}
}
