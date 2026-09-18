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
	want := memberPayload{ID: cassetteAdmin, Username: cassetteAdmin, DisplayName: cassetteAdmin, IsAdmin: true, IsActive: true}
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

// TestGitHubPeriodTypesConformance is the conformance gate for the two
// period-scoped evidence types (pull_request, deployment). It runs the shared
// harness against a FAKE-API-backed plugin rather than a cassette: the pulls /
// reviews / check-runs / deployments / statuses endpoints are not in the
// committed cassette, and hand-writing interactions for them would assert our
// own guesses about GitHub's response shapes rather than the real ones.
// Cassette coverage (and the matching OpenAPI-slice routes in
// github_spec_conformance_test.go) is therefore DEFERRED until a live
// re-record against the test org can capture genuine responses.
//
// What this still gates, which is most of the value: determinism across two
// Collects, ID-ascending sort order, JSON Schema validation of every emitted
// payload, and payload completeness (no schema-declared property dropped).
// The vendor-JSON → domain-struct mapping in httpAPI is covered by the
// httptest unit tests in github_test.go.
func TestGitHubPeriodTypesConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	merged := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deployed := time.Date(2026, 3, 2, 9, 15, 0, 0, time.UTC)

	// RunConformance passes no slot params, so the plugin falls back to a
	// trailing one-year window ending at the injected clock; every fixture
	// timestamp below sits inside it.
	api := &fakeAPI{
		pulls: []PullRequest{
			{
				Repository: cassetteOrg + "/" + repoProtected, Number: 42,
				Author: cassetteAdmin, MergedBy: "e2e-reviewer", TargetBranch: "main",
				MergeCommitSHA: "e2e00000000000000000000000000000000000ab", MergedAt: merged,
				Reviews: []Review{
					{User: "e2e-reviewer", State: "APPROVED", SubmittedAt: merged.Add(-time.Hour)},
				},
				CheckRuns: []CheckRun{{Status: "completed", Conclusion: "success"}},
			},
			{
				// Self-approved, no CI: the failing side of both derived booleans.
				Repository: cassetteOrg + "/" + repoUnprotected, Number: 7,
				Author: cassetteAdmin, TargetBranch: "main", MergedAt: merged.Add(24 * time.Hour),
				Reviews: []Review{
					{User: cassetteAdmin, State: "APPROVED", SubmittedAt: merged},
				},
			},
		},
		deployments: []Deployment{
			{
				Repository: cassetteOrg + "/" + repoProtected, ID: "900",
				SHA: "e2e00000000000000000000000000000000000ab", Environment: "production",
				ProductionEnvironment: true, Creator: cassetteAdmin,
				CreatedAt: deployed, State: "success",
			},
			{
				// No creator, no statuses: empty deployed_by and "unknown" status.
				Repository: cassetteOrg + "/" + repoUnprotected, ID: "12",
				Environment: "staging", CreatedAt: deployed.Add(time.Hour),
			},
		},
	}
	types := sourcetest.BuiltinEvidenceTypes(t)
	newPlugin := func() core.SourcePlugin {
		return New(Options{API: api, Org: cassetteOrg, Now: func() time.Time { return fixedNow }})
	}

	prRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypePullRequest}},
		EvidenceTypes: types,
	})
	deployRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newPlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDeployment}},
		EvidenceTypes: types,
	})

	// Record IDs are the strings a customer writes in a waiver's resource_id,
	// so they are part of the contract, not an implementation detail.
	wantPRIDs := []string{cassetteOrg + "/" + repoProtected + "#42", cassetteOrg + "/" + repoUnprotected + "#7"}
	assertIDs(t, prRecs, wantPRIDs)
	wantDeployIDs := []string{
		cassetteOrg + "/" + repoProtected + "/deployments/900",
		cassetteOrg + "/" + repoUnprotected + "/deployments/12",
	}
	assertIDs(t, deployRecs, wantDeployIDs)

	prs := map[string]pullRequestPayload{}
	for _, r := range prRecs {
		var p pullRequestPayload
		mustUnmarshal(t, r.Payload, &p)
		prs[r.ID] = p
	}
	reviewed := prs[cassetteOrg+"/"+repoProtected+"#42"]
	if reviewed.ApprovalCount != 1 || reviewed.IndependentApprovalCount != 1 ||
		!reviewed.ApprovedBeforeMerge || !reviewed.ChecksPassed {
		t.Errorf("independently reviewed PR = %+v", reviewed)
	}
	selfApproved := prs[cassetteOrg+"/"+repoUnprotected+"#7"]
	if selfApproved.IndependentApprovalCount != 0 ||
		selfApproved.ApprovedBeforeMerge || selfApproved.ChecksPassed {
		t.Errorf("self-approved PR = %+v", selfApproved)
	}

	deploys := map[string]deploymentPayload{}
	for _, r := range deployRecs {
		var d deploymentPayload
		mustUnmarshal(t, r.Payload, &d)
		deploys[r.ID] = d
	}
	prod := deploys[cassetteOrg+"/"+repoProtected+"/deployments/900"]
	if !prod.IsProduction || prod.Status != "success" {
		t.Errorf("production deployment = %+v", prod)
	}
	staging := deploys[cassetteOrg+"/"+repoUnprotected+"/deployments/12"]
	if staging.IsProduction || staging.Status != "unknown" || staging.DeployedBy != "" {
		t.Errorf("staging deployment = %+v", staging)
	}
}

// assertIDs checks the emitted record IDs as a set (the harness already
// asserts they are sorted ascending).
func assertIDs(t *testing.T, records []core.EvidenceRecord, want []string) {
	t.Helper()
	got := map[string]bool{}
	for _, r := range records {
		got[r.ID] = true
	}
	if len(got) != len(want) {
		t.Fatalf("record count = %d, want %d", len(got), len(want))
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("missing record ID %q; got %v", id, got)
		}
	}
}
