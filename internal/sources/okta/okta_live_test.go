//go:build live

package okta

import (
	"context"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// okta_live_test.go: L4a Okta live drift test (WU-4.4). Runs the real plugin
// against a live Okta org and schema-validates every record (users, MFA factors,
// SAML/OIDC apps), catching upstream shape changes and mapper regressions on the
// scheduled run. Gated on credentials; skips cleanly without them.
//
//	OKTA_TEST_TOKEN    a long-lived Okta API token (SSWS scheme)
//	OKTA_TEST_ORG_URL  the org base URL, e.g. https://example.okta.com
func TestOktaLive(t *testing.T) {
	env := sourcetest.RequireEnv(t, "OKTA_TEST_TOKEN", "OKTA_TEST_ORG_URL")
	ctx := context.Background()
	p, err := NewFromConfig(ctx, env["OKTA_TEST_ORG_URL"], env["OKTA_TEST_TOKEN"])
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

	if counts[EvidenceTypeDirectoryUser] < 1 {
		t.Errorf("directory_user = %d, want >= 1", counts[EvidenceTypeDirectoryUser])
	}
	if counts[EvidenceTypeApp] < 1 {
		t.Errorf("okta_app = %d, want >= 1", counts[EvidenceTypeApp])
	}
}
