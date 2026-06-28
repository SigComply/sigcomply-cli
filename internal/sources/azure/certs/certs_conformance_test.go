package certs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// certs_conformance_test.go: azure.tls_certificate L1+L2 (WU-2.12). Hand-authored:
// one App Service certificate (auto_renew omitted) + one certificate order
// (managed, auto-renew on). Both valid into 2027.
func TestAzureCertsConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealCerts(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/certificates"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
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
		if p.DaysUntilExpiry <= 0 {
			t.Errorf("cert %s days_until_expiry = %d, want > 0", p.ID, p.DaysUntilExpiry)
		}
		if p.IsManaged {
			managed++
		}
	}
	if managed != 1 {
		t.Errorf("managed certs = %d, want 1 (the order)", managed)
	}
}
