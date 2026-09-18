package gitlab

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// gitlab_conformance_test.go is the GitLab plugin's L1+L2 contract test
// (WU-2.10), mirroring the GitHub plugin (internal/sources/github/). It replays
// a sanitized go-vcr cassette recorded against a real GitLab group through the
// official client-go SDK deserializer and the shared sourcetest harness —
// schema, completeness, determinism, metadata — for git_repository and
// directory_user, offline.
//
// GitLab has no fixture-vs-spec layer (cf. github_spec_conformance_test.go):
// GitLab's published OpenAPI is too thin to cover the projects/members/
// protected-branches endpoints this plugin calls (see §2/§5 of the strategy
// doc — GitLab leans on L4a live re-record diffs instead).
//
// Re-record (maintainer step; the PRIVATE-TOKEN auth header is scrubbed on
// save): build an sdkAPI whose gitlab.Client uses sourcetest.RecordClient via
// gitlab.WithHTTPClient and Collect against a live group, then neutralize the
// group path and member username to the placeholders below.
const (
	cassetteGroup   = "e2e-group"
	repoProtected   = "e2e-group/e2e-protected"
	repoUnprotected = "e2e-group/e2e-unprotected"
	memberOwner     = "e2e-owner"
)

func TestGitLabConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		client, err := gitlab.NewClient("test-token", // ignored on replay (auth header REDACTED)
			gitlab.WithBaseURL(defaultBaseURL),
			gitlab.WithHTTPClient(sourcetest.ReplayClient(t, "testdata/cassettes/group_collect")),
		)
		if err != nil {
			t.Fatalf("gitlab client: %v", err)
		}
		return New(Options{
			API: &sdkAPI{client: client, group: cassetteGroup},
			Now: func() time.Time { return fixedNow },
		})
	}
	// One plugin (one replay client) per evidence type; the harness's two
	// Collect runs reuse it via the cassette's replayable interactions.
	types := sourcetest.BuiltinEvidenceTypes(t)
	repoOptional := []string{"git_repository.created_at"}
	userOptional := []string{
		"directory_user.email",
		"directory_user.mfa_factor_count",
		"directory_user.is_service_account",
		"directory_user.is_external",
		"directory_user.last_login_at",
		"directory_user.created_at",
	}

	repoRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newPlugin(),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}},
		EvidenceTypes:  types,
		OptionalFields: repoOptional,
	})
	userRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newPlugin(),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}},
		EvidenceTypes:  types,
		OptionalFields: userOptional,
	})

	repos := map[string]repoPayload{}
	for _, r := range repoRecs {
		var p repoPayload
		mustUnmarshal(t, r.Payload, &p)
		repos[r.ID] = p
	}
	users := map[string]memberPayload{}
	for _, r := range userRecs {
		var p memberPayload
		mustUnmarshal(t, r.Payload, &p)
		users[r.ID] = p
	}

	// Branch-protection present vs absent on the two stable projects (the group
	// also carries transient deletion_scheduled projects, so don't pin a count).
	assertProtected(t, repos, repoProtected, true)
	assertProtected(t, repos, repoUnprotected, false)
	if got := repos[repoProtected]; !got.IsPrivate {
		t.Errorf("%s is_private = false, want true", repoProtected)
	}

	// The group Owner: is_admin (AccessLevel >= Maintainer), active. MFA is
	// best-effort false on gitlab.com (two_factor_enabled needs an
	// instance-admin token — the documented group-owner-token caveat).
	got, ok := users[memberOwner]
	if !ok {
		t.Fatalf("missing directory_user %q; got %v", memberOwner, keys(users))
	}
	if !got.IsAdmin || !got.IsActive || got.Username != memberOwner {
		t.Errorf("%s = %+v; want is_admin && is_active && username %q", memberOwner, got, memberOwner)
	}
}

func assertProtected(t *testing.T, repos map[string]repoPayload, id string, want bool) {
	t.Helper()
	got, ok := repos[id]
	if !ok {
		t.Fatalf("missing git_repository %q; got %v", id, keys(repos))
	}
	if got.DefaultBranchProtected != want {
		t.Errorf("%s default_branch_protected = %v, want %v", id, got.DefaultBranchProtected, want)
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

// TestGitLabPeriodTypesConformance is the conformance gate for the two
// period-scoped evidence types (pull_request, deployment). It runs the shared
// harness against a FAKE-API-backed plugin rather than the cassette: the group
// merge-requests, approvals, MR-pipelines and deployments endpoints are not in
// the committed cassette, and hand-writing interactions for them would assert
// our own guesses about GitLab's response shapes rather than the real ones.
// Cassette coverage is therefore DEFERRED until a live re-record against the
// test group can capture genuine responses.
//
// What this still gates, which is most of the value: determinism across two
// Collects, ID-ascending sort order, JSON Schema validation of every emitted
// payload, and payload completeness (no schema-declared property dropped).
// The vendor-JSON → domain-struct mapping in sdkAPI is covered by the httptest
// unit tests in gitlab_test.go.
func TestGitLabPeriodTypesConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	merged := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deployed := time.Date(2026, 3, 2, 9, 15, 0, 0, time.UTC)

	// RunConformance passes no slot params, so the plugin falls back to a
	// trailing one-year window ending at the injected clock; every fixture
	// timestamp below sits inside it.
	api := &fakeAPI{
		pulls: []PullRequest{
			{
				Repository: repoProtected, Number: 42, Author: memberOwner,
				MergedBy: "e2e-reviewer", TargetBranch: "main",
				MergeCommitSHA: "e2e00000000000000000000000000000000000ab", MergedAt: merged,
				Approvers: []string{"e2e-reviewer"}, ChecksPassed: true,
			},
			{
				// Self-approved, no pipeline: the failing side of both
				// derived booleans.
				Repository: repoUnprotected, Number: 7, Author: memberOwner,
				TargetBranch: "main", MergedAt: merged.Add(24 * time.Hour),
				Approvers: []string{memberOwner},
			},
		},
		deployments: []Deployment{
			{
				Repository: repoProtected, ID: "900",
				SHA: "e2e00000000000000000000000000000000000ab", Environment: "production",
				EnvironmentTier: "production", Creator: memberOwner,
				CreatedAt: deployed, Status: "success",
			},
			{
				// No user, no tier, no status: empty deployed_by, name-based
				// is_production=false, and an "unknown" status.
				Repository: repoUnprotected, ID: "12",
				Environment: "staging", CreatedAt: deployed.Add(time.Hour),
			},
		},
	}
	types := sourcetest.BuiltinEvidenceTypes(t)
	newFakePlugin := func() core.SourcePlugin {
		return New(Options{API: api, Now: func() time.Time { return fixedNow }})
	}

	prRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newFakePlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypePullRequest}},
		EvidenceTypes: types,
	})
	deployRecs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        newFakePlugin(),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDeployment}},
		EvidenceTypes: types,
	})

	// Record IDs are the strings a customer writes in a waiver's resource_id,
	// so they are part of the contract, not an implementation detail.
	wantPRIDs := []string{repoProtected + "#42", repoUnprotected + "#7"}
	if got := recordIDs(prRecs); !reflect.DeepEqual(got, wantPRIDs) {
		t.Errorf("pull_request IDs = %v; want %v", got, wantPRIDs)
	}
	wantDeployIDs := []string{
		repoProtected + "/deployments/900",
		repoUnprotected + "/deployments/12",
	}
	if got := recordIDs(deployRecs); !reflect.DeepEqual(got, wantDeployIDs) {
		t.Errorf("deployment IDs = %v; want %v", got, wantDeployIDs)
	}
}
