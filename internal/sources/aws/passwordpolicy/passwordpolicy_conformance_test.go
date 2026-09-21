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
		OptionalFields: []string{
			// mfa_required is per-user in IAM, not a password-policy
			// attribute (a *bool with omitempty — never emitted for AWS).
			"password_policy.v2.mfa_required",
			// The recorded account has no password policy at all, so the
			// record is complexity_model "none" and carries no per-class
			// answer. The schema's discriminated union is what keeps a
			// per_class record from dropping them silently.
			"password_policy.v2.requires_uppercase",
			"password_policy.v2.requires_lowercase",
			"password_policy.v2.requires_numbers",
			"password_policy.v2.requires_symbols",
			// IAM's account password policy has no name, and every
			// attribute of it is tenant-configurable.
			"password_policy.v2.name",
			"password_policy.v2.password_strength",
			"password_policy.v2.complexity_description",
			"password_policy.v2.not_configurable",
		},
	})

	if len(recs) != 1 {
		t.Fatalf("password_policy records = %d, want 1 (account singleton)", len(recs))
	}
	var p passwordPolicyPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if recs[0].ID != singletonID || p.Provider == "" {
		t.Errorf("record id=%q provider=%q; want account / non-empty provider", recs[0].ID, p.Provider)
	}
	// No policy → weakest posture: no minimum, and no strength
	// requirement of any kind (not a per-class answer of four noes).
	if p.MinLength != 0 || p.ComplexityModel != complexityNone {
		t.Errorf("payload = %+v; want min_length 0 and complexity_model %q (no policy set)", p, complexityNone)
	}
}
