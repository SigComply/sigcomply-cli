package github

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// github_conformance_test.go is the GitHub plugin's L2 contract test
// (WU-1.3). It replays a sanitized go-vcr cassette recorded against a real
// org through the *real* JSON deserializer and the shared sourcetest
// conformance harness — schema-validating, completeness-checking, and
// determinism-checking every git_repository and directory_user record, with
// zero network access. The cassette captures both a branch-protected and an
// unprotected repo plus an org member, so the per-policy-relevant fields are
// exercised, not just the happy path.
//
// Re-recording (maintainer step; secrets are scrubbed before write): build an
// httpAPI around sourcetest.RecordClient and drive Collect against the live
// org, then neutralize the org/login to the placeholders below:
//
//	api := &httpAPI{org: org, token: token, base: "https://api.github.com",
//	    client: sourcetest.RecordClient(t, "testdata/cassettes/org_collect", http.DefaultTransport)}
//	New(Options{API: api, Org: org}).Collect(ctx, core.SlotRequest{
//	    AcceptedTypes: []string{EvidenceTypeRepository, EvidenceTypeDirectoryUser}})

// Placeholders the committed cassette was scrubbed to (the real org/login are
// never written to disk). The replay plugin must be configured with the same
// org so the URLs it builds match the recorded interactions.
const (
	cassetteOrg     = "e2e-test-org"
	cassetteAdmin   = "e2e-admin"
	repoProtected   = "e2e-protected"
	repoUnprotected = "e2e-unprotected"
)

func TestGitHubConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	api := &httpAPI{
		org:    cassetteOrg,
		token:  "test-token", // ignored on replay (auth header is REDACTED in the cassette)
		base:   "https://api.github.com",
		client: sourcetest.ReplayClient(t, "testdata/cassettes/org_collect"),
	}
	types := sourcetest.BuiltinEvidenceTypes(t)
	// Fields the directory_user/git_repository schemas declare but the GitHub
	// org-listing endpoints do not expose, so the plugin legitimately omits
	// them (it never emits a null/sentinel — Inv #4).
	optional := []string{
		"git_repository.created_at",
		"directory_user.email",
		"directory_user.mfa_factor_count",
		"directory_user.is_service_account",
		"directory_user.last_login_at",
		"directory_user.created_at",
	}

	// Conformance is run per evidence type: each Collect group is sorted by ID
	// within its type (the collector splits records by Type downstream), so the
	// harness's ID-sort check is per-type, not across the mixed output.
	newPlugin := func() core.SourcePlugin {
		return New(Options{API: api, Org: cassetteOrg, Now: func() time.Time { return fixedNow }})
	}
	repoRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newPlugin(),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}},
		EvidenceTypes:  types,
		OptionalFields: optional,
	})
	userRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newPlugin(),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}},
		EvidenceTypes:  types,
		OptionalFields: optional,
	})

	// Scenario assertions on top of the harness's schema/completeness checks:
	// the cassette must yield exactly the two repos and the one member.
	repos := map[string]repoPayload{}
	users := map[string]memberPayload{}
	for _, r := range repoRecs {
		var p repoPayload
		mustUnmarshal(t, r.Payload, &p)
		repos[r.ID] = p
	}
	for _, r := range userRecs {
		var p memberPayload
		mustUnmarshal(t, r.Payload, &p)
		users[r.ID] = p
	}

	if len(repos) != 2 {
		t.Fatalf("git_repository records = %d, want 2 (%v)", len(repos), keys(repos))
	}
	if len(users) != 1 {
		t.Fatalf("directory_user records = %d, want 1 (%v)", len(users), keys(users))
	}

	// Branch-protection present: e2e-protected has a protection rule with one
	// required reviewer and Dependabot alerts on (204 probe).
	assertRepo(t, repos, repoProtected, repoPayload{
		Name: repoProtected, DefaultBranch: "main",
		DefaultBranchProtected: true, RequiredReviewersCount: 1,
		DependabotAlertsEnabled: true, IsPrivate: false,
	})
	// Branch-protection absent: e2e-unprotected (private repo, protection
	// endpoint denied) has no protection and Dependabot alerts off (404 probe).
	assertRepo(t, repos, repoUnprotected, repoPayload{
		Name: repoUnprotected, DefaultBranch: "main",
		DefaultBranchProtected: false, RequiredReviewersCount: 0,
		DependabotAlertsEnabled: false, IsPrivate: true,
	})

	// The org member: an admin without 2FA, active, internal (not an outside
	// collaborator). Exercises is_admin/is_active/is_external mapping.
	got, ok := users[cassetteAdmin]
	if !ok {
		t.Fatalf("missing directory_user %q; got %v", cassetteAdmin, keys(users))
	}
	want := memberPayload{ID: cassetteAdmin, DisplayName: cassetteAdmin, IsAdmin: true, IsActive: true}
	if got != want {
		t.Errorf("%s payload = %+v; want %+v", cassetteAdmin, got, want)
	}
}

// assertRepo checks the policy-relevant subset of a git_repository payload
// (protection, reviewers, dependabot, visibility) against want, by ID.
func assertRepo(t *testing.T, repos map[string]repoPayload, id string, want repoPayload) {
	t.Helper()
	got, ok := repos[id]
	if !ok {
		t.Fatalf("missing git_repository %q; got %v", id, keys(repos))
	}
	switch {
	case got.Name != want.Name:
		t.Errorf("%s name = %q, want %q", id, got.Name, want.Name)
	case got.DefaultBranch != want.DefaultBranch:
		t.Errorf("%s default_branch = %q, want %q", id, got.DefaultBranch, want.DefaultBranch)
	case got.DefaultBranchProtected != want.DefaultBranchProtected:
		t.Errorf("%s default_branch_protected = %v, want %v", id, got.DefaultBranchProtected, want.DefaultBranchProtected)
	case got.RequiredReviewersCount != want.RequiredReviewersCount:
		t.Errorf("%s required_reviewers_count = %d, want %d", id, got.RequiredReviewersCount, want.RequiredReviewersCount)
	case got.DependabotAlertsEnabled != want.DependabotAlertsEnabled:
		t.Errorf("%s dependabot_alerts_enabled = %v, want %v", id, got.DependabotAlertsEnabled, want.DependabotAlertsEnabled)
	case got.IsPrivate != want.IsPrivate:
		t.Errorf("%s is_private = %v, want %v", id, got.IsPrivate, want.IsPrivate)
	}
}

func mustUnmarshal(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
