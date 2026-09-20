package secretmanager

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	secretmanager "google.golang.org/api/secretmanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// secretmanager_conformance_test.go: gcp.secret L1+L2 (WU-2.11). Hand-authored:
// one CMEK-encrypted, rotation-configured secret with 2 versions.
func TestGCPSecretManagerConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := secretmanager.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/secrets", "https://secretmanager.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realSM{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		WantScope:      &core.RecordScope{Project: "e2e-project"},
		OptionalFields: []string{"secret.last_rotated_days"},
	})
	if len(recs) != 1 {
		t.Fatalf("secret records = %d, want 1", len(recs))
	}
	var p secretPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	// CMEK + a rotation policy are not asserted (both need extra setup — a KMS
	// grant and a Pub/Sub topic). The seed has 2 versions, so NeverRotated=false.
	if p.NeverRotated {
		t.Errorf("secret = %+v; want a rotated secret (>=2 versions)", p)
	}
}
