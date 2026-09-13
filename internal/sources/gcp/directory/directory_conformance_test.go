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

// directory_conformance_test.go: gcp.directory L1+L2 (WU-2.11). Hand-authored
// (no live GCP cred): an active admin with 2SV and an organization external
// ID, an active non-admin without 2SV (non-organization external ID only),
// and an archived user with 2SV and an organization external ID.

// newCassettePlugin replays testdata/cassettes/users through the real Admin
// SDK deserializer.
func newCassettePlugin(t *testing.T) core.SourcePlugin {
	t.Helper()
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	svc, err := admin.NewService(context.Background(),
		gcptest.ReplayOptions(t, "testdata/cassettes/users", "https://admin.googleapis.com")...)
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{API: &realDirectory{svc: svc}, Customer: "my_customer", Now: func() time.Time { return fixedNow }})
}

func TestGCPDirectoryConformance(t *testing.T) {
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newCassettePlugin(t), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"directory_user.username", // primaryEmail is the only login
			"directory_user.mfa_factor_count", "directory_user.is_service_account",
			"directory_user.is_external", "directory_user.last_login_at", "directory_user.created_at",
		},
	})
	if len(recs) != 3 {
		t.Fatalf("directory_user records = %d, want 3", len(recs))
	}
	var admins, mfa, active int
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
		if p.IsActive {
			active++
		}
	}
	if admins != 1 || mfa != 2 || active != 2 {
		t.Errorf("admins=%d mfa=%d active=%d, want 1/2/2 (archived user inactive)", admins, mfa, active)
	}
}

func TestGCPDirectoryRosterConformance(t *testing.T) {
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newCassettePlugin(t), Request: core.SlotRequest{AcceptedTypes: []string{RosterEvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			// employee_id: only users with an "organization" external ID (bob has none).
			"roster_entry.employee_id",
			// Workspace carries no employee-type or service-account signal.
			"roster_entry.employee_type", "roster_entry.is_service_account",
		},
	})
	want := []rosterPayload{
		{ID: "100200300", Status: "active", SourceStatus: "active", Email: "alice@example.com", DisplayName: "Alice Admin", EmployeeID: "E-1001"},
		{ID: "100200301", Status: "active", SourceStatus: "active", Email: "bob@example.com", DisplayName: "Bob User"},
		{ID: "100200302", Status: "inactive", SourceStatus: "archived", Email: "carol@example.com", DisplayName: "Carol Former", EmployeeID: "E-1002"},
	}
	if len(recs) != len(want) {
		t.Fatalf("roster_entry records = %d, want %d", len(recs), len(want))
	}
	for i, r := range recs {
		var p rosterPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p != want[i] {
			t.Errorf("roster[%d] = %+v; want %+v", i, p, want[i])
		}
	}
}
