package securityservices

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// securityservices_conformance_test.go: aws.security_service L1+L2 (WU-2.6).
// Multi-service plugin (Macie + Inspector + SecurityHub) — one cassette covers
// all three endpoints. Recorded against the account with the services not
// enabled, exercising the graceful AccessDenied/NotFound -> is_enabled=false
// path; the plugin always emits exactly three records.
func TestSecurityServicesConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		cfg := awstest.ReplayConfig(t, "testdata/cassettes/services")
		api := &awsClients{
			macie:       macie2.NewFromConfig(cfg),
			inspector:   inspector2.NewFromConfig(cfg),
			securityhub: securityhub.NewFromConfig(cfg),
		}
		return New(Options{API: api, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 3 {
		t.Fatalf("security_service records = %d, want 3 (macie/inspector/securityhub)", len(recs))
	}
	types := map[string]bool{}
	for _, r := range recs {
		var p servicePayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		types[p.ServiceType] = true
	}
	for _, want := range []string{"dlp", "vulnerability_scanner", "siem"} {
		if !types[want] {
			t.Errorf("missing service_type %q (got %v)", want, types)
		}
	}
}
