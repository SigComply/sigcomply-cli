package network

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

// network_conformance_test.go: gcp.network L1+L2 (WU-2.11). Hand-authored: one
// VPC with a subnet that has flow logs enabled.
func TestGCPNetworkConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := gce.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/networks", "https://compute.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realNetwork{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"network.region", "network.cidr_block"},
	})
	if len(recs) != 1 {
		t.Fatalf("network records = %d, want 1", len(recs))
	}
	var p networkPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.FlowLogsEnabled || !p.IsDefault {
		t.Errorf("network = %+v; want default with flow logs", p)
	}
}
