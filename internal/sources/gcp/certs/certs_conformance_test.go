package certs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	certificatemanager "google.golang.org/api/certificatemanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// certs_conformance_test.go: gcp.tls_certificate L1+L2 (WU-2.11). Hand-authored:
// one Google-managed cert (auto-renew) + one self-managed (auto_renew omitted).
func TestGCPCertsConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := certificatemanager.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/certificates", "https://certificatemanager.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realCertManager{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"tls_certificate.auto_renew"},
	})
	if len(recs) != 2 {
		t.Fatalf("tls_certificate records = %d, want 2", len(recs))
	}
	var managed int
	for _, r := range recs {
		var p certPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.IsManaged {
			managed++
		}
		if p.DaysUntilExpiry <= 0 {
			t.Errorf("cert %s days_until_expiry = %d, want > 0", p.ID, p.DaysUntilExpiry)
		}
	}
	if managed != 1 {
		t.Errorf("managed certs = %d, want 1", managed)
	}
}
