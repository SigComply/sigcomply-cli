package okta

import (
	"net/url"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// okta_spec_conformance_test.go is the Okta plugin's L2 fixture-vs-spec check
// (WU-2.8), mirroring github_spec_conformance_test.go. It validates the
// recorded cassette's response bodies against a committed slice of Okta's own
// OpenAPI model (contracts/okta/management@<date>.json) so a cassette that
// drifts from the real shape fails offline.
const oktaSpecSlice = "../../../contracts/okta/management@2026-06-28.json"

// OpenAPI component names the Okta operations' 200 bodies must satisfy.
const (
	compUser       = "User"
	compUserFactor = "UserFactor"
)

// oktaSpecRoute maps a recorded request (method + URL path) to the OpenAPI
// component its 200 array body must satisfy. Two endpoints are deliberately
// not strictly spec-validated:
//   - /roles returns an inline oneOf[StandardRole, CustomRole] (no single named
//     component) and only feeds the is_admin boolean.
//   - /apps (Application): Okta's *own* published schema marks several fields
//     non-nullable (e.g. accessibility.{loginRedirectUrl,errorRedirectUrl})
//     that the live API returns as null — a known inaccuracy in Okta's spec, on
//     fields the plugin doesn't consume. Validating whole Application bodies
//     against it yields false positives, so the okta_app mapping relies on the
//     conformance test (okta_conformance_test.go) instead. The contract slice
//     still ships the Application schema for the scheduled L3 drift job.
//
// Both are covered by conformance; User and UserFactor (whose schemas are
// accurate) carry the L2 fixture-vs-spec guard here.
func oktaSpecRoute(method, rawURL string) (component string, matched bool) {
	if method != "GET" {
		return "", false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	p := u.Path
	switch {
	case strings.HasSuffix(p, "/factors"):
		return compUserFactor, true
	case strings.HasSuffix(p, "/users"):
		return compUser, true
	}
	return "", false
}

func TestOktaSpecConformance(t *testing.T) {
	spec := sourcetest.NewSpecValidator(t, oktaSpecSlice)
	interactions := sourcetest.LoadCassetteInteractions(t, "testdata/cassettes/org_collect")

	validated := map[string]int{}
	for _, in := range interactions {
		component, matched := oktaSpecRoute(in.Request.Method, in.Request.URL)
		if !matched {
			continue
		}
		if in.Response.Code < 200 || in.Response.Code >= 300 {
			continue
		}
		value, ok := sourcetest.DecodeJSONBody(t, in.Response.Body)
		if !ok {
			continue
		}
		arr, isArr := value.([]any)
		if !isArr {
			t.Errorf("%s %s: expected JSON array body, got %T", in.Request.Method, in.Request.URL, value)
			continue
		}
		validated[component] += len(arr)
		if err := spec.CheckArray(component, value); err != nil {
			t.Errorf("%s %s: response body off-spec: %v", in.Request.Method, in.Request.URL, err)
		}
	}

	wantAtLeast := map[string]int{
		compUser:       3, // the three seeded users
		compUserFactor: 1, // the one MFA-enrolled user's factor
	}
	for component, min := range wantAtLeast {
		if validated[component] < min {
			t.Errorf("validated %d %q bodies against spec, want >= %d (cassette no longer covers this operation?)",
				validated[component], component, min)
		}
	}
}

// TestOktaSpecValidatorRejectsOffSpecBody is the acceptance check: mutating a
// recorded body to an off-spec shape must fail validation.
func TestOktaSpecValidatorRejectsOffSpecBody(t *testing.T) {
	spec := sourcetest.NewSpecValidator(t, oktaSpecSlice)
	interactions := sourcetest.LoadCassetteInteractions(t, "testdata/cassettes/org_collect")

	var user map[string]any
	for _, in := range interactions {
		if c, ok := oktaSpecRoute(in.Request.Method, in.Request.URL); !ok || c != compUser {
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
		t.Fatal("no User body in cassette to mutate")
	}
	if err := spec.Check(compUser, user); err != nil {
		t.Fatalf("baseline User should conform, got: %v", err)
	}

	// status is a required enum on the Okta User; an invalid value must fail.
	mutated := make(map[string]any, len(user))
	for k, v := range user {
		mutated[k] = v
	}
	mutated["status"] = "NOT_A_STATUS"
	if err := spec.Check(compUser, mutated); err == nil {
		t.Error("off-spec body (invalid status enum) passed validation; the spec gate has no teeth")
	}
}
