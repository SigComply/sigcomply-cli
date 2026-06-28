//go:build live

package entra

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// entra_live_test.go: L4a Entra ID live drift test (WU-4.5). Builds the real
// app-only credential from the AZURE_* env (DefaultAzureCredential chain),
// confirms it can mint a Graph token, then runs the plugin. The MFA
// registration report (userRegistrationDetails) needs an Entra P1/P2 license;
// on a non-premium tenant the plugin errors by design (never emits false MFA),
// so this test treats that specific error as a clean skip (auth already proven)
// and otherwise schema-validates the directory_user records. Gated on creds.
//
//	AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET  app-only Graph creds
func TestEntraLive(t *testing.T) {
	env := sourcetest.RequireEnv(t, "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
	ctx := context.Background()

	cred, err := azcommon.NewCredential()
	if err != nil {
		t.Fatal(err)
	}
	// Real auth assertion: the SP must be able to mint a Graph token.
	if err := azcommon.VerifyCredential(ctx, cred, azcommon.ScopeGraph); err != nil {
		t.Fatalf("graph credential: %v", err)
	}

	p := NewFromGraph(cred, azcommon.Config{TenantID: env["AZURE_TENANT_ID"]})
	recs, err := p.Collect(ctx, core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		// The MFA registration report is Entra-P1/P2-gated; reaching that error
		// proves auth + AuditLog.Read.All worked (a bad token 401s earlier).
		if strings.Contains(err.Error(), "P1/P2") {
			t.Skipf("graph auth OK; MFA registration report is Entra-P1/P2-gated on this tenant (expected): %v", err)
		}
		t.Fatalf("collect: %v", err)
	}

	types := sourcetest.BuiltinEvidenceTypes(t)
	for i := range recs {
		r := &recs[i]
		et, ok := types.Lookup(r.Type)
		if !ok {
			t.Errorf("record %s: no registered evidence type", r.Type)
			continue
		}
		if err := evidencetypes.Validate(et.Schema, r.Payload); err != nil {
			t.Errorf("record %s (%s): schema drift: %v", r.ID, r.Type, err)
		}
	}
	t.Logf("collected %d directory_user records", len(recs))
	if len(recs) < 1 {
		t.Errorf("directory_user = %d, want >= 1", len(recs))
	}
}
