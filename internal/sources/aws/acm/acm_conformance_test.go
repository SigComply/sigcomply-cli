package acm

import (
	"encoding/json"
	"testing"
	"time"

	awsacm "github.com/aws/aws-sdk-go-v2/service/acm"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// acm_conformance_test.go: aws.tls_certificate L1+L2 (WU-2.6). Hand-authored
// (a real issued cert needs domain validation): one AMAZON_ISSUED cert.
func TestACMConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awsacm.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/certificates"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("tls_certificate records = %d, want 1", len(recs))
	}
	var p certPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsManaged || p.Status != "ISSUED" || p.DaysUntilExpiry <= 0 {
		t.Errorf("cert = %+v; want managed, ISSUED, positive days-until-expiry", p)
	}
}
