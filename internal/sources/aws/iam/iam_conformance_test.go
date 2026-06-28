package iam

import (
	"encoding/json"
	"testing"
	"time"

	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// iam_conformance_test.go is the aws.iam plugin's L1+L2 contract test (WU-2.2).
// It replays a sanitized go-vcr cassette recorded against a real account
// through the real IAM (query-protocol) SDK deserializer and the shared
// sourcetest harness, for directory_user.v2 records, offline. The IAM AWS query
// operations share one URL, so this exercises sourcetest.AWSMatcher's body
// disambiguation (WU-2.1).
//
// Re-record: build the IAM client from awstest.RecordConfig and Collect against
// a live account (pre-warming the credential report so GetCredentialReport
// returns ready in one call), then scrub usernames/UserIds and the base64
// credential-report CSV to placeholders.
func TestIAMConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client := awsiam.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/iam_users"))
		return New(Options{
			API:    client,
			Region: awstest.Region,
			Now:    func() time.Time { return fixedNow },
			Sleep:  func(time.Duration) {},
		})
	}

	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		// Fields the IAM identity surface doesn't populate (the plugin never
		// emits a null/sentinel for them — Inv #4).
		OptionalFields: []string{
			"directory_user.v2.mfa_factor_count",
			"directory_user.v2.is_service_account",
			"directory_user.v2.is_external",
			"directory_user.v2.groups",
			"directory_user.v2.email",
			"directory_user.v2.last_login_at",
			"directory_user.v2.created_at",
		},
	})

	users := map[string]userPayload{}
	for _, r := range recs {
		var p userPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		users[r.ID] = p
	}

	// Two IAM users + the synthetic root record from the credential report.
	if len(users) != 3 {
		t.Fatalf("directory_user.v2 records = %d, want 3 (%v)", len(users), keysOf(users))
	}
	var roots, mfa, programmatic int
	var root userPayload
	for _, u := range users {
		if u.IsRoot {
			roots++
			root = u
		}
		if u.MFAEnabled {
			mfa++
		}
		if u.HasProgrammaticAccess {
			programmatic++
		}
	}
	if roots != 1 {
		t.Errorf("is_root count = %d, want 1", roots)
	}
	if mfa != 0 {
		t.Errorf("mfa_enabled count = %d, want 0 (account has no MFA)", mfa)
	}
	// Both real IAM users have an active access key.
	if programmatic < 2 {
		t.Errorf("has_programmatic_access count = %d, want >= 2", programmatic)
	}
	// Root has a console password but no MFA and no access keys.
	if !root.HasConsoleAccess || root.MFAEnabled || root.HasProgrammaticAccess {
		t.Errorf("root = %+v; want console access, no MFA, no programmatic access", root)
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
