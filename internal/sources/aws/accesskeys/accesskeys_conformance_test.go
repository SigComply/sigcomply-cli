package accesskeys

import (
	"encoding/json"
	"testing"
	"time"

	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// accesskeys_conformance_test.go is the aws.iam_access_key plugin's L1+L2
// contract test (WU-2.2): replays a sanitized cassette through the real IAM
// SDK deserializer + the sourcetest harness, offline. Distinct access-key IDs
// rely on the per-key redaction placeholder (sourcetest.redactAccessKey) so the
// two keys keep distinct record IDs.
func TestAccessKeysConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client := awsiam.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/access_keys"))
		return New(Options{API: client, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}

	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		// last_used_days is omitted for a never-used key (a *int with omitempty).
		OptionalFields: []string{"iam_access_key.last_used_days"},
	})

	keys := map[string]keyPayload{}
	for _, r := range recs {
		var p keyPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		keys[r.ID] = p
	}
	if len(keys) != 2 {
		t.Fatalf("iam_access_key records = %d, want 2 (distinct key IDs)", len(keys))
	}
	for id, k := range keys {
		if !k.IsActive {
			t.Errorf("key %s is_active = false, want true", id)
		}
		if k.AgeDays < 0 {
			t.Errorf("key %s age_days = %d, want >= 0", id, k.AgeDays)
		}
	}
}
