package artifactregistry

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	artifactregistry "google.golang.org/api/artifactregistry/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// artifactregistry_conformance_test.go: gcp.container_registry L1+L2 (WU-2.11).
// Hand-authored: one private DOCKER repo with scan-on-push + immutable tags +
// CMEK (locations → repositories → per-repo IAM walk).
func TestGCPArtifactRegistryConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := artifactregistry.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/repositories", "https://artifactregistry.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realAR{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("container_registry records = %d, want 1", len(recs))
	}
	var p registryPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.ScanOnPushEnabled || !p.ImageImmutabilityEnabled || !p.EncryptionEnabled || p.IsPublic {
		t.Errorf("repo = %+v; want scan-on-push, immutable, encrypted, private", p)
	}
}
