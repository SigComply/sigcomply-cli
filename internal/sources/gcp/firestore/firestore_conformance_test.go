package firestore

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	firestore "google.golang.org/api/firestore/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// firestore_conformance_test.go: gcp.nosql_table L1+L2 (WU-2.11). Hand-authored:
// the (default) database with PITR + deletion protection + CMEK.
func TestGCPFirestoreConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := firestore.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/databases", "https://firestore.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realFirestore{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"nosql_table.stream_enabled"},
	})
	if len(recs) != 1 {
		t.Fatalf("nosql_table records = %d, want 1", len(recs))
	}
	var p databasePayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.EncryptionEnabled || !p.PointInTimeRecoveryEnabled || !p.DeletionProtection {
		t.Errorf("db = %+v; want encrypted, PITR, deletion-protected", p)
	}
}
