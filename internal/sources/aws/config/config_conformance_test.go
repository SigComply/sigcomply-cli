package config

import (
	"encoding/json"
	"testing"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/service/configservice"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// config_conformance_test.go: aws.config_change_tracking L1+L2 (WU-2.5).
// Cassette is hand-authored (a Config recorder bills per item): one recorder,
// recording all resource types.
func TestConfigConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awscfg.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/recorders"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("config_change_tracking records = %d, want 1", len(recs))
	}
	var p recorderPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsRecording || !p.AllResourceTypes {
		t.Errorf("recorder = %+v; want recording all resource types", p)
	}
}
