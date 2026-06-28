//go:build live

package github

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// github_live_test.go: L4a GitHub live drift test (WU-4.2). Runs the real plugin
// against a live org and schema-validates every collected record, so an upstream
// GitHub REST shape change (or a mapper regression) is caught on the scheduled
// run — the half of drift detection that L3 spec-diffing can't see (behavior).
// Gated on credentials; skips cleanly without them.
//
//	GITHUB_TEST_TOKEN  PAT with repo + read:org + admin:org (org policy + 2FA)
//	GITHUB_TEST_ORG    an org whose members are required to use 2FA
func TestGitHubLive(t *testing.T) {
	env := sourcetest.RequireEnv(t, "GITHUB_TEST_TOKEN", "GITHUB_TEST_ORG")
	ctx := context.Background()
	p, err := NewFromToken(ctx, env["GITHUB_TEST_ORG"], env["GITHUB_TEST_TOKEN"])
	if err != nil {
		t.Fatal(err)
	}
	recs, err := p.Collect(ctx, core.SlotRequest{AcceptedTypes: p.Emits()})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	types := sourcetest.BuiltinEvidenceTypes(t)
	counts := map[string]int{}
	for i := range recs {
		r := &recs[i]
		counts[r.Type]++
		et, ok := types.Lookup(r.Type)
		if !ok {
			t.Errorf("record %s: no registered evidence type", r.Type)
			continue
		}
		if err := evidencetypes.Validate(et.Schema, r.Payload); err != nil {
			t.Errorf("record %s (%s): schema drift: %v", r.ID, r.Type, err)
		}
	}
	t.Logf("collected: %v", counts)

	if counts[EvidenceTypeRepository] < 1 {
		t.Errorf("git_repository = %d, want >= 1", counts[EvidenceTypeRepository])
	}
	if counts[EvidenceTypeDirectoryUser] < 1 {
		t.Errorf("directory_user = %d, want >= 1", counts[EvidenceTypeDirectoryUser])
	}
	if counts[EvidenceTypeOrgPolicy] != 1 {
		t.Fatalf("source_control_org_policy = %d, want exactly 1", counts[EvidenceTypeOrgPolicy])
	}
	for i := range recs {
		if recs[i].Type != EvidenceTypeOrgPolicy {
			continue
		}
		var op orgPolicyPayload
		if err := json.Unmarshal(recs[i].Payload, &op); err != nil {
			t.Fatal(err)
		}
		if !op.TwoFactorRequired {
			t.Error("org policy two_factor_required = false; want true (GITHUB_TEST_ORG must enforce 2FA)")
		}
	}
}
