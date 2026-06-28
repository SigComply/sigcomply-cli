package directory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	admin "google.golang.org/api/admin/directory/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gcptest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// directory_conformance_test.go: gcp.directory_user L1+L2 (WU-2.11). Hand-authored
// (no live GCP cred): an admin with 2SV + a non-admin without.
func TestGCPDirectoryConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		svc, err := admin.NewService(context.Background(),
			gcptest.ReplayOptions(t, "testdata/cassettes/users", "https://admin.googleapis.com")...)
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: &realDirectory{svc: svc}, Customer: "my_customer", Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"directory_user.mfa_factor_count", "directory_user.is_service_account",
			"directory_user.is_external", "directory_user.last_login_at", "directory_user.created_at",
		},
	})
	if len(recs) != 2 {
		t.Fatalf("directory_user records = %d, want 2", len(recs))
	}
	var admins, mfa int
	for _, r := range recs {
		var p userPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.IsAdmin {
			admins++
		}
		if p.MFAEnabled {
			mfa++
		}
	}
	if admins != 1 || mfa != 1 {
		t.Errorf("admins=%d mfa=%d, want 1/1", admins, mfa)
	}
}
