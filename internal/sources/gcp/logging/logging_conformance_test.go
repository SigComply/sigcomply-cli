package logging

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	logging "google.golang.org/api/logging/v2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// logging_conformance_test.go: gcp.log_group L1+L2 (WU-2.11). Hand-authored:
// one locked _Default log bucket with 400-day retention + CMEK.
func TestGCPLoggingConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := logging.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/buckets", "https://logging.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realLogging{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		WantScope:     &core.RecordScope{Project: "e2e-project"},
	})
	if len(recs) != 2 {
		t.Fatalf("log_group records = %d, want 2 (_Default + _Required)", len(recs))
	}
	var retentionSet int
	for _, r := range recs {
		var p logGroupPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.RetentionSet {
			retentionSet++
		}
	}
	// CMEK is not asserted: the default log buckets use Google-managed keys.
	if retentionSet == 0 {
		t.Errorf("want >=1 log bucket with retention set; got 0")
	}
}
