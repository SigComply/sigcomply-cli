package asset

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	cloudasset "google.golang.org/api/cloudasset/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// asset_conformance_test.go: gcp.config_change_tracking L1+L2 (WU-2.11).
// Hand-authored: one Asset Inventory feed covering all asset types.
func TestGCPAssetConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := cloudasset.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/feeds", "https://cloudasset.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realAsset{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("config_change_tracking records = %d, want 1", len(recs))
	}
	var p trackingPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsRecording || !p.AllResourceTypes {
		t.Errorf("tracking = %+v; want recording all resource types", p)
	}
}
