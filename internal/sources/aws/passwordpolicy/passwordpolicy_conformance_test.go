package passwordpolicy

import (
	"encoding/json"
	"testing"
	"time"

	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// passwordpolicy_conformance_test.go is the aws.password_policy plugin's L1+L2
// contract test (WU-2.2). The recorded account has NO password policy, so the
// cassette captures the NoSuchEntity response and the plugin emits the single
// weakest-posture record.
func TestPasswordPolicyConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client := awsiam.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/password_policy"))
		return New(Options{API: client, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}

	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		// mfa_required is per-user in IAM, not a password-policy attribute (a
		// *bool with omitempty — never emitted for AWS).
		OptionalFields: []string{"password_policy.mfa_required"},
	})

	if len(recs) != 1 {
		t.Fatalf("password_policy records = %d, want 1 (account singleton)", len(recs))
	}
	var p passwordPolicyPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if recs[0].ID != "account" || p.Provider == "" {
		t.Errorf("record id=%q provider=%q; want account / non-empty provider", recs[0].ID, p.Provider)
	}
	// No policy → weakest posture.
	if p.MinLength != 0 || p.RequiresUppercase || p.RequiresSymbols {
		t.Errorf("payload = %+v; want all-zero (no policy set)", p)
	}
}
