package guardduty

import (
	"encoding/json"
	"testing"
	"time"

	awsgd "github.com/aws/aws-sdk-go-v2/service/guardduty"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// guardduty_conformance_test.go: aws.threat_detection_service L1+L2 (WU-2.6).
// Recorded against a provisioned, enabled detector.
func TestGuardDutyConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awsgd.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/detectors"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"threat_detection_service.region"},
	})
	if len(recs) != 1 {
		t.Fatalf("threat_detection_service records = %d, want 1", len(recs))
	}
	var p detectorPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsEnabled {
		t.Errorf("detector = %+v; want enabled", p)
	}
}
