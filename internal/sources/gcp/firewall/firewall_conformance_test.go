package firewall

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

// firewall_conformance_test.go: gcp.firewall_rule L1+L2 (WU-2.11). Hand-authored:
// an INGRESS rule open to 0.0.0.0/0.
func TestGCPFirewallConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := gce.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/firewalls", "https://compute.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realFirewall{svc: svc}, ProjectID: "e2e-project", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"firewall_rule.source_cidr", "firewall_rule.dest_cidr"},
	})
	if len(recs) < 1 {
		t.Fatalf("firewall_rule records = %d, want >= 1", len(recs))
	}
	var open bool
	for _, r := range recs {
		var p rulePayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.IsUnrestrictedIPv4 {
			open = true
		}
	}
	if !open {
		t.Error("expected an unrestricted-IPv4 ingress rule")
	}
}
