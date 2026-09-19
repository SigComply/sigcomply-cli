package okta

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// okta_conformance_test.go is the Okta plugin's L1+L2 contract test (WU-2.8),
// mirroring the GitHub plugin (see internal/sources/github/). It replays a
// sanitized go-vcr cassette recorded against a real Okta org through the real
// deserializer and the shared sourcetest harness — schema, completeness,
// determinism, metadata — for directory_user and okta_app records, offline.
// roster_entry replays a separate hand-authored cassette (roster_collect) —
// the seeded org has no deprovisioned user, and org_collect stays a faithful
// recording — covering both listing passes and every status bucket.
//
// Re-record (maintainer step; the SSWS auth header is scrubbed on save):
// build an httpAPI around sourcetest.RecordClient and Collect against a live
// org, then neutralize the org subdomain to the placeholder below.
const (
	cassetteBase = "https://example.okta.com"
	cassetteOrg  = "example.okta.com"
)

// newCassettePlugin builds the real plugin around a replayed cassette.
func newCassettePlugin(t *testing.T, cassette string) core.SourcePlugin {
	t.Helper()
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	api := &httpAPI{
		base:   cassetteBase,
		token:  "test-token", // ignored on replay (auth header is REDACTED)
		client: sourcetest.ReplayClient(t, cassette),
	}
	return New(Options{API: api, Org: cassetteOrg, Now: func() time.Time { return fixedNow }})
}

func TestOktaConformance(t *testing.T) {
	newPlugin := func() core.SourcePlugin { return newCassettePlugin(t, "testdata/cassettes/org_collect") }
	types := sourcetest.BuiltinEvidenceTypes(t)

	// directory_user: Okta's user/factor/role endpoints don't expose these
	// schema fields, so the plugin legitimately omits them.
	userRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}},
		EvidenceTypes: types,
		OptionalFields: []string{
			"directory_user.username", // login is email-shaped
			"directory_user.is_service_account",
			"directory_user.is_external",
			"directory_user.created_at",
			"directory_user.last_login_at",
			"directory_user.email",
			"directory_user.display_name",
		},
	})
	appRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeApp}},
		EvidenceTypes: types,
	})

	users := map[string]userPayload{}
	for _, r := range userRecs {
		var p userPayload
		mustUnmarshal(t, r.Payload, &p)
		users[r.ID] = p
	}
	apps := map[string]appPayload{}
	for _, r := range appRecs {
		var p appPayload
		mustUnmarshal(t, r.Payload, &p)
		apps[r.ID] = p
	}

	assertUserAggregates(t, users)
	assertFederatedApps(t, apps)
}

// assertUserAggregates checks the seeded-org invariants: 3 users, two active
// (ACTIVE and PASSWORD_EXPIRED map to is_active; PROVISIONED does not), at
// least one admin, and exactly one MFA-enrolled (the org is seeded with a
// single MFA user).
func assertUserAggregates(t *testing.T, users map[string]userPayload) {
	t.Helper()
	var active, admins, mfa int
	for _, u := range users {
		if u.IsActive {
			active++
		}
		if u.IsAdmin {
			admins++
		}
		if u.MFAEnabled {
			mfa++
		}
	}
	t.Logf("users=%d active=%d admins=%d mfa=%d", len(users), active, admins, mfa)
	switch {
	case len(users) != 3:
		t.Errorf("directory_user records = %d, want 3", len(users))
	case active != 2:
		t.Errorf("active users = %d, want 2 (ACTIVE + PASSWORD_EXPIRED map to is_active; PROVISIONED does not)", active)
	case admins < 1:
		t.Errorf("admin users = %d, want >= 1 (org has an admin)", admins)
	case mfa != 1:
		t.Errorf("mfa-enabled users = %d, want 1 (org seeded with 1 MFA user)", mfa)
	}
}

// TestOktaRosterConformance replays roster_collect: a two-page default listing
// (ACTIVE, STAGED, SUSPENDED, LOCKED_OUT) plus the DEPROVISIONED filter pass,
// with no per-user factor/role calls recorded — any such call would miss the
// cassette and fail the replay.
func TestOktaRosterConformance(t *testing.T) {
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newCassettePlugin(t, "testdata/cassettes/roster_collect"),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRosterEntry}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{
			"roster_entry.is_service_account", // Okta has no service-account flag on users
			"roster_entry.employee_id",        // employeeNumber is optional per user
			"roster_entry.employee_type",      // userType is optional per user
		},
	})
	want := map[string]struct{ status, sourceStatus, displayName string }{
		"00uRosterActive00698": {rosterActive, oktaStatusActive, "Ada Example"},
		"00uRosterStaged00698": {rosterPending, oktaStatusStaged, "Carol Example"},
		"00uRosterSuspend0698": {rosterInactive, oktaStatusSuspended, "Dave Example"},
		"00uRosterLocked00698": {rosterActive, oktaStatusLockedOut, "frank@example.com"}, // no names → login
		"00uRosterDeprov00698": {rosterInactive, oktaStatusDeprovisioned, "Erin Example"},
	}
	if len(recs) != len(want) {
		t.Fatalf("roster_entry records = %d, want %d", len(recs), len(want))
	}
	for _, r := range recs {
		var p rosterPayload
		mustUnmarshal(t, r.Payload, &p)
		w, ok := want[r.ID]
		if !ok {
			t.Errorf("unexpected roster entry %q", r.ID)
			continue
		}
		if p.Status != w.status || p.SourceStatus != w.sourceStatus || p.DisplayName != w.displayName {
			t.Errorf("%s = %s/%s/%q, want %s/%s/%q", r.ID, p.Status, p.SourceStatus, p.DisplayName,
				w.status, w.sourceStatus, w.displayName)
		}
		if r.IdentityKey == "" || r.IdentityKey != p.Email {
			t.Errorf("%s IdentityKey = %q, want lowercased email %q", r.ID, r.IdentityKey, p.Email)
		}
	}
}

// assertFederatedApps checks that at least one SAML/OIDC app is present and that
// federating sign-on modes map to mfa_required=true.
func assertFederatedApps(t *testing.T, apps map[string]appPayload) {
	t.Helper()
	if len(apps) < 1 {
		t.Fatalf("okta_app records = %d, want >= 1", len(apps))
	}
	var sawFederated bool
	for _, a := range apps {
		if a.SignOnMode != signOnModeSAML && a.SignOnMode != "OPENID_CONNECT" {
			continue
		}
		sawFederated = true
		if !a.MFARequired {
			t.Errorf("app %q (%s) mfa_required = false, want true", a.ID, a.SignOnMode)
		}
	}
	if !sawFederated {
		t.Error("expected at least one SAML/OIDC app in the cassette")
	}
}

func mustUnmarshal(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
}
