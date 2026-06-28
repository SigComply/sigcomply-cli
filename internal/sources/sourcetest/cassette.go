package sourcetest

import (
	"net/http"
	"regexp"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

// This file is the L2 HTTP record/replay seam (WU-1.2). A plugin's test points
// its HTTP client at a recorded cassette and replays it offline through the
// real SDK deserializer. Recording is a maintainer/live-test step that scrubs
// secrets to the §4 placeholders before anything touches disk.

// ReplayClient returns an *http.Client that replays the named go-vcr cassette
// with no network access. cassetteName is the path without the ".yaml" suffix
// (e.g. "testdata/cassettes/list_repos"); replay errors if a request was not
// pre-recorded, which is what keeps the per-PR suite deterministic and offline.
//
// Interactions are replayable, so the same cassette serves a plugin that hits
// an endpoint more than once and the conformance harness's two Collect runs.
func ReplayClient(t *testing.T, cassetteName string) *http.Client {
	t.Helper()
	rec, err := recorder.New(
		cassetteName,
		recorder.WithMode(recorder.ModeReplayOnly),
		recorder.WithSkipRequestLatency(true),
		recorder.WithReplayableInteractions(true),
		recorder.WithMatcher(MethodURLMatcher),
	)
	if err != nil {
		t.Fatalf("sourcetest: load cassette %q: %v", cassetteName, err)
	}
	t.Cleanup(func() {
		if err := rec.Stop(); err != nil {
			t.Errorf("sourcetest: stop recorder: %v", err)
		}
	})
	return rec.GetDefaultClient()
}

// RecordClient returns an *http.Client that records real traffic into the named
// cassette on first run (then replays), scrubbing every interaction to the §4
// placeholders via RedactInteraction before it is written. This is the
// maintainer/live path (build-tagged or one-off), never the per-PR suite. A nil
// realTransport defaults to http.DefaultTransport.
func RecordClient(t *testing.T, cassetteName string, realTransport http.RoundTripper) *http.Client {
	t.Helper()
	if realTransport == nil {
		realTransport = http.DefaultTransport
	}
	rec, err := recorder.New(
		cassetteName,
		recorder.WithMode(recorder.ModeRecordOnce),
		recorder.WithRealTransport(realTransport),
		recorder.WithReplayableInteractions(true),
		recorder.WithMatcher(MethodURLMatcher),
		recorder.WithHook(RedactInteraction, recorder.BeforeSaveHook),
	)
	if err != nil {
		t.Fatalf("sourcetest: open cassette %q for recording: %v", cassetteName, err)
	}
	t.Cleanup(func() {
		if err := rec.Stop(); err != nil {
			t.Errorf("sourcetest: stop recorder: %v", err)
		}
	})
	return rec.GetDefaultClient()
}

// MethodURLMatcher matches a live request to a recorded interaction on method +
// URL only. The strict v4 default also compares headers and bodies, which
// breaks the moment a credential header (redacted in the cassette) differs from
// the live token — exactly what redaction guarantees. Method+URL is the stable
// identity of a read-only collection request.
//
//nolint:gocritic // signature is fixed by cassette.MatcherFunc (value receiver).
func MethodURLMatcher(r *http.Request, i cassette.Request) bool {
	return r.Method == i.Method && r.URL.String() == i.URL
}

// Redaction patterns mirror the §4 placeholder table. Order matters: specific
// secrets are scrubbed before the broad 12-digit account-ID sweep (which also
// zeroes the account field inside any ARN).
var (
	reAccessKey   = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reBearer      = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`)
	reEmail       = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reAccountID   = regexp.MustCompile(`\b\d{12}\b`)
	exampleDomain = regexp.MustCompile(`@example\.(com|org|net)$`)

	// Header names whose entire value is a secret — replaced wholesale.
	sensitiveHeaders = map[string]bool{
		"Authorization":        true,
		"Proxy-Authorization":  true,
		"Cookie":               true,
		"Set-Cookie":           true,
		"X-Api-Key":            true,
		"X-Amz-Security-Token": true,
		"X-Amz-Credential":     true,
		"X-Goog-Api-Key":       true,
		"Private-Token":        true, // GitLab PAT (canonical form of PRIVATE-TOKEN)
		"Job-Token":            true, // GitLab CI job token
	}
)

// RedactInteraction is the go-vcr BeforeSaveHook that scrubs a recorded
// interaction's headers, URL, and bodies to the stable §4 placeholders, so a
// committed cassette never leaks identity and the WU-0.3 fixture gate passes.
// (Username/login scrubbing beyond email-style logins is field-specific and is
// a plugin's responsibility via an additional hook, not this generic pass.)
func RedactInteraction(i *cassette.Interaction) error {
	scrubHeaders(i.Request.Headers)
	scrubHeaders(i.Response.Headers)
	i.Request.URL = scrubString(i.Request.URL)
	i.Request.Body = scrubString(i.Request.Body)
	i.Response.Body = scrubString(i.Response.Body)
	return nil
}

func scrubHeaders(h http.Header) {
	for name, vals := range h {
		if sensitiveHeaders[http.CanonicalHeaderKey(name)] {
			h[name] = []string{"REDACTED"}
			continue
		}
		for k, v := range vals {
			vals[k] = scrubString(v)
		}
	}
}

func scrubString(s string) string {
	s = reAccessKey.ReplaceAllString(s, "AKIAEXAMPLE0000000000")
	s = reBearer.ReplaceAllString(s, "Bearer REDACTED")
	s = reEmail.ReplaceAllStringFunc(s, func(m string) string {
		if exampleDomain.MatchString(m) {
			return m // already a reserved placeholder domain
		}
		return "user@example.com"
	})
	s = reAccountID.ReplaceAllString(s, "000000000000")
	return s
}
