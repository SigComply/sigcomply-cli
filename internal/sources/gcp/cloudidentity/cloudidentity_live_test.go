//go:build live

package cloudidentity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// cloudidentity_live_test.go: L4a Cloud Identity live drift test. It
// matters more here than for any other source in the tree, because this
// is the ONLY test that can see the real wire.
//
// Google publishes no sample response body for
// settings/security.password, so three details are asserted by this
// package rather than verified: the JSON shape of expirationDuration
// (Duration string or integer — the decoder takes both), whether a
// tenant always returns at least one password policy (this plugin
// handles zero), and the exact field encodings generally. An L2 cassette
// was deliberately NOT written, because a fixture hand-authored from
// those guesses would test the guesses. THIS test is what turns them
// into facts: point it at a real Workspace tenant and it logs the raw
// policy payloads it saw, schema-validates every emitted record, and
// fails on anything the decoders cannot take.
//
// Running it once against a real tenant is also what unblocks recording
// the cassette (go-vcr against this same client), which is the step that
// closes the gap for good. Until then the absence is documented in the
// package doc and in docs/architecture/12-multicloud-sources.md.
//
// Access is SUPER-ADMIN ONLY, via domain-wide delegation with
// cloud-identity.policies.readonly allow-listed VERBATIM:
//
//	GCP_TEST_TARGET_SERVICE_ACCOUNT  the delegated service account's email
//	GCP_TEST_IMPERSONATE_SUBJECT     a Workspace super admin's email
//
// ADC must already be configured for an identity holding
// roles/iam.serviceAccountTokenCreator on that service account.
func TestCloudIdentityLive(t *testing.T) {
	env := sourcetest.RequireEnv(t, "GCP_TEST_TARGET_SERVICE_ACCOUNT", "GCP_TEST_IMPERSONATE_SUBJECT")
	ctx := context.Background()
	p, err := NewFromGCP(ctx, AuthConfig{
		TargetServiceAccount: env["GCP_TEST_TARGET_SERVICE_ACCOUNT"],
		ImpersonateSubject:   env["GCP_TEST_IMPERSONATE_SUBJECT"],
	})
	if err != nil {
		t.Fatalf("build plugin: %v", err)
	}

	// The raw listing first, and logged: this is the observation the whole
	// package is currently missing, so it is worth printing even when
	// everything passes. A run of this test is the record of what the wire
	// actually looks like.
	raw, err := p.api.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	var passwordPolicies int
	for _, pol := range raw {
		if pol == nil || pol.Setting == nil || pol.Setting.Type != settingTypePassword {
			continue
		}
		passwordPolicies++
		t.Logf("policy %s type=%s sortOrder=%v value=%s",
			pol.Name, pol.Type, querySortOrder(pol.PolicyQuery), string(pol.Setting.Value))
	}
	t.Logf("listing carried %d policies, %d of them settings/security.password", len(raw), passwordPolicies)

	recs, err := p.Collect(ctx, core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		// A decode failure here is the discovery this test exists for: it
		// means the wire shape is outside everything setting.go accepts.
		t.Fatalf("collect: %v", err)
	}
	if len(recs) != passwordPolicies {
		t.Errorf("records = %d, want one per password policy (%d)", len(recs), passwordPolicies)
	}

	types := sourcetest.BuiltinEvidenceTypes(t)
	for i := range recs {
		r := &recs[i]
		et, ok := types.Lookup(r.Type)
		if !ok {
			t.Errorf("record %s: no registered evidence type %q", r.ID, r.Type)
			continue
		}
		if err := evidencetypes.Validate(et.Schema, r.Payload); err != nil {
			t.Errorf("record %s: schema drift: %v", r.ID, err)
		}
		t.Logf("emitted %s", string(r.Payload))
	}

	// Zero password policies is a legitimate tenant state and the plugin
	// handles it (no records, no synthesized defaults) — but if this test
	// ever runs against a tenant with none, it has verified nothing about
	// the wire, which is the one thing it is here for. Say so loudly
	// rather than passing quietly.
	if passwordPolicies == 0 {
		t.Skip("tenant returned no settings/security.password policy: the wire shape is still unverified — " +
			"point this test at a tenant with a configured password policy")
	}

	// A last belt-and-braces read of the decoded values: every record must
	// carry the three fields Google can always answer, because after the
	// reduction each one is either set by an administrator or carries the
	// documented default.
	for i := range recs {
		var got map[string]json.RawMessage
		if err := json.Unmarshal(recs[i].Payload, &got); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"min_length", "max_age_days", "reuse_prevented"} {
			if _, ok := got[k]; !ok {
				t.Errorf("record %s is missing %q", recs[i].ID, k)
			}
		}
	}
}
