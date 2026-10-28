package soc2_test

import (
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// The all-users MFA policy covers people who can sign in interactively. A
// programmatic-only IAM user (has_console_access false) has no console
// password to protect; a v1 record does not say, so it stays in scope.
func TestMFAAllUsers_ScopedToInteractiveUsers(t *testing.T) {
	const id = "soc2.cc6.1.mfa_enforced_all_users"
	user := func(typ string, p map[string]any) core.EvidenceRecord {
		p["id"], p["mfa_enabled"] = "u1", false
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return core.EvidenceRecord{ID: "u1", Type: typ, SourceID: "aws.iam", Payload: b}
	}
	for name, tc := range map[string]struct {
		rec  core.EvidenceRecord
		want core.PolicyStatus
	}{
		"v2 console user without MFA":      {user("directory_user.v2", map[string]any{"has_console_access": true}), core.StatusFail},
		"v2 programmatic user without MFA": {user("directory_user.v2", map[string]any{"has_console_access": false}), core.StatusPass},
		"v1 user without MFA (no signal)":  {user("directory_user", map[string]any{}), core.StatusFail},
	} {
		t.Run(name, func(t *testing.T) {
			if got := evalPolicy(t, id, map[string][]core.EvidenceRecord{slotEvidence: {tc.rec}}); got.Status != tc.want {
				t.Errorf("status = %q (%v); want %q", got.Status, got.Diag, tc.want)
			}
		})
	}
}
