package github

import (
	"net/url"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// github_spec_conformance_test.go is the GitHub plugin's L2 fixture-vs-spec
// check (WU-1.4). It replays the recorded cassette's response bodies against a
// committed slice of GitHub's own OpenAPI model
// (contracts/github/api.github.com@<date>.json) so a cassette that drifts from
// the real response shape — or a spec slice updated past what we record —
// fails offline. This guards the *raw vendor responses* the mappers are
// written against; github_conformance_test.go guards the *mapped records*.
//
// Refresh the spec slice with scripts (added in Phase 3) or by re-running the
// extraction documented in contracts/README.md; bump the @<date> filename and
// specSlice below together.
const specSlice = "../../../contracts/github/api.github.com@2026-06-28.json"

// OpenAPI component names the GitHub operations' 200 bodies must satisfy.
const (
	compMinimalRepo      = "minimal-repository"
	compSimpleUser       = "simple-user"
	compOrgMembership    = "org-membership"
	compBranchProtection = "branch-protection"
)

// specRoute maps a recorded request (method + URL path) to the OpenAPI
// component its 200 body must satisfy. Routes mirror the operations
// internal/sources/github calls; interactions with no route (the 204/404
// vulnerability-alerts probe, the 403 protection denial) carry no schema body
// and are skipped.
func specRoute(method, rawURL string) (component string, isArray, matched bool) {
	if method != "GET" {
		return "", false, false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false, false
	}
	p := u.Path
	switch {
	case strings.HasSuffix(p, "/repos"):
		return compMinimalRepo, true, true
	case strings.HasSuffix(p, "/members"):
		return compSimpleUser, true, true
	case strings.HasSuffix(p, "/outside_collaborators"):
		return compSimpleUser, true, true
	case strings.Contains(p, "/memberships/"):
		return compOrgMembership, false, true
	case strings.HasSuffix(p, "/protection"):
		return compBranchProtection, false, true
	}
	return "", false, false
}

func TestGitHubSpecConformance(t *testing.T) {
	spec := sourcetest.NewSpecValidator(t, specSlice)
	interactions := sourcetest.LoadCassetteInteractions(t, "testdata/cassettes/org_collect")

	// Count what we validated per component so a cassette that silently stops
	// covering an operation can't pass as a no-op.
	validated := map[string]int{}
	for _, in := range interactions {
		component, isArray, matched := specRoute(in.Request.Method, in.Request.URL)
		if !matched {
			continue
		}
		// Only success bodies carry the schema shape (403/404 are error bodies).
		if in.Response.Code < 200 || in.Response.Code >= 300 {
			continue
		}
		value, ok := sourcetest.DecodeJSONBody(t, in.Response.Body)
		if !ok {
			continue
		}
		var err error
		if isArray {
			arr, isArr := value.([]any)
			if !isArr {
				t.Errorf("%s %s: expected JSON array body, got %T", in.Request.Method, in.Request.URL, value)
				continue
			}
			validated[component] += len(arr)
			err = spec.CheckArray(component, value)
		} else {
			validated[component]++
			err = spec.Check(component, value)
		}
		if err != nil {
			t.Errorf("%s %s: response body off-spec: %v", in.Request.Method, in.Request.URL, err)
		}
	}

	// The cassette must still exercise each operation it was recorded for.
	wantAtLeast := map[string]int{
		compMinimalRepo:      2, // e2e-protected + e2e-unprotected
		compSimpleUser:       1, // the org member
		compOrgMembership:    1, // its role lookup
		compBranchProtection: 1, // e2e-protected (e2e-unprotected's is a 403)
	}
	for component, min := range wantAtLeast {
		if validated[component] < min {
			t.Errorf("validated %d %q bodies against spec, want >= %d (cassette no longer covers this operation?)",
				validated[component], component, min)
		}
	}
}

// TestSpecValidatorRejectsOffSpecBody is the WU-1.4 acceptance check: mutating a
// recorded body to an off-spec shape must fail validation. It proves the gate
// has teeth — a clean pass in TestGitHubSpecConformance means the bodies really
// conform, not that the validator is a no-op.
func TestSpecValidatorRejectsOffSpecBody(t *testing.T) {
	spec := sourcetest.NewSpecValidator(t, specSlice)
	interactions := sourcetest.LoadCassetteInteractions(t, "testdata/cassettes/org_collect")

	// Grab a real simple-user (the org members list) and corrupt a required
	// typed field: id is a required integer in GitHub's spec.
	var user map[string]any
	for _, in := range interactions {
		if c, _, ok := specRoute(in.Request.Method, in.Request.URL); !ok || c != compSimpleUser {
			continue
		}
		value, ok := sourcetest.DecodeJSONBody(t, in.Response.Body)
		if !ok {
			continue
		}
		if arr, ok := value.([]any); ok && len(arr) > 0 {
			if m, ok := arr[0].(map[string]any); ok {
				user = m
				break
			}
		}
	}
	if user == nil {
		t.Fatal("no simple-user body in cassette to mutate")
	}

	// Sanity: the unmutated body conforms.
	if err := spec.Check(compSimpleUser, user); err != nil {
		t.Fatalf("baseline simple-user should conform, got: %v", err)
	}

	// Mutate the required integer id to a string → must be rejected.
	mutated := cloneMap(user)
	mutated["id"] = "not-an-integer"
	if err := spec.Check(compSimpleUser, mutated); err == nil {
		t.Error("off-spec body (id as string) passed validation; the spec gate has no teeth")
	}
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
