package gke

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	container "google.golang.org/api/container/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// gke_conformance_test.go: gcp.kubernetes_cluster L1+L2 (WU-2.11). Hand-authored:
// a private, secrets-encrypted, logging-enabled, auto-upgrading cluster.
func TestGCPGKEConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := container.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/clusters", "https://container.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realGKE{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("kubernetes_cluster records = %d, want 1", len(recs))
	}
	var p clusterPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.SecretsEncryptionEnabled || !p.LoggingEnabled || !p.IsPrivateEndpoint {
		t.Errorf("cluster = %+v; want secrets-encryption, logging, private endpoint", p)
	}
}
