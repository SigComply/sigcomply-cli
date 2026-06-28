package compute

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	gce "google.golang.org/api/compute/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// compute_conformance_test.go: gcp.compute_instance L1+L2 (WU-2.7). GCP has no
// usable test credential (org blocks SA keys/impersonation), so the cassette is
// hand-authored: canned aggregatedList JSON served via httptest at record time,
// replayed here against the real endpoint. One shielded, private, encrypted,
// running instance.
func TestGCPComputeConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := gce.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/instances", "https://compute.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realCompute{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"compute_instance.monitoring_enabled", "compute_instance.metadata_service_hardened"},
	})
	if len(recs) != 1 {
		t.Fatalf("compute_instance records = %d, want 1", len(recs))
	}
	var p instancePayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsRunning || p.HasPublicIP || !p.ShieldedVMEnabled {
		t.Errorf("instance = %+v; want running, no public IP, shielded VM", p)
	}
}
