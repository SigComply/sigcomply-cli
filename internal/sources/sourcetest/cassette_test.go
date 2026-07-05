package sourcetest

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
)

func TestReplayClient_ReplaysOffline(t *testing.T) {
	client := ReplayClient(t, "testdata/cassettes/sample")

	// Replay twice to prove interactions are replayable (the conformance
	// harness calls Collect twice) and deterministic.
	for i := 0; i < 2; i++ {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/ping", http.NoBody)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("run %d: do: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("run %d: close body: %v", i, cerr)
		}
		if err != nil {
			t.Fatalf("run %d: read body: %v", i, err)
		}
		if got := strings.TrimSpace(string(body)); got != `{"ok":true}` {
			t.Fatalf("run %d: body = %q; want {\"ok\":true}", i, got)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("run %d: status = %d; want 200", i, resp.StatusCode)
		}
	}
}

func TestReplayClient_UnrecordedRequestErrors(t *testing.T) {
	client := ReplayClient(t, "testdata/cassettes/sample")
	// A request with no matching interaction must error (no network fallback);
	// on error the response is nil, so there is no body to close.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/not-recorded", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err == nil {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("close body: %v", cerr)
		}
		t.Fatal("expected error for unrecorded request, got nil")
	}
}

func TestMethodURLMatcher(t *testing.T) {
	rec := cassette.Request{Method: http.MethodGet, URL: "https://api.example.com/x"}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/x", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if !MethodURLMatcher(req, rec) {
		t.Error("expected match on identical method+URL")
	}
	other, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.example.com/x", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if MethodURLMatcher(other, rec) {
		t.Error("expected no match on differing method")
	}
}

func TestRedactInteraction(t *testing.T) {
	i := &cassette.Interaction{
		Request: cassette.Request{
			Method:  "POST",
			URL:     "https://api.example.com/q?token=Bearer%20abcDEF123456",
			Headers: http.Header{"Authorization": {"Bearer sk_live_abcdef123456"}, "Private-Token": {"glpat-realsecrettoken1234"}, "Accept": {"application/json"}},
			Body:    `{"actor":"alice@acmecorp.com"}`,
			Form:    map[string][]string{"AccessKeyId": {"AKIAIOSFODNN7EXAMPLE9"}},
		},
		Response: cassette.Response{
			Headers: http.Header{"Set-Cookie": {"session=deadbeef"}, "Content-Type": {"application/json"}},
			Body: `{"key":"AKIAIOSFODNN7EXAMPLE1","arn":"arn:aws:iam::123456789012:user/bob",` +
				`"account":"210987654321","owner":"carol@acmecorp.com","auth":"Bearer ghp_secrettoken123"}`,
		},
	}
	if err := RedactInteraction(i); err != nil {
		t.Fatalf("RedactInteraction: %v", err)
	}

	// Sensitive headers fully redacted (incl. GitLab's PRIVATE-TOKEN).
	const redacted = "REDACTED"
	for _, h := range []struct {
		name, got string
	}{
		{"Authorization", i.Request.Headers.Get("Authorization")},
		{"Set-Cookie", i.Response.Headers.Get("Set-Cookie")},
		{"Private-Token", i.Request.Headers.Get("Private-Token")},
	} {
		if h.got != redacted {
			t.Errorf("%s = %q; want %s", h.name, h.got, redacted)
		}
	}
	// Non-sensitive header preserved.
	if got := i.Request.Headers.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q; want preserved", got)
	}

	// Bodies + URL scrubbed to placeholders; no real identity survives.
	checkScrubbed(t, "request URL", i.Request.URL)
	checkScrubbed(t, "request body", i.Request.Body)
	checkScrubbed(t, "response body", i.Response.Body)

	// Spot-check specific placeholder substitutions in the response body.
	rb := i.Response.Body
	for _, want := range []string{"AKIAEXAMPLE", "000000000000", "user@example.com", "Bearer REDACTED"} {
		if !strings.Contains(rb, want) {
			t.Errorf("response body missing placeholder %q: %s", want, rb)
		}
	}
	if strings.Contains(rb, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("response body still contains the original access key: %s", rb)
	}
	// The parsed request Form is scrubbed too (it mirrors a form-encoded body).
	if got := i.Request.Form["AccessKeyId"][0]; strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") || !strings.Contains(got, "AKIAEXAMPLE") {
		t.Errorf("request Form not scrubbed: %q", got)
	}
	if strings.Contains(rb, "123456789012") || strings.Contains(rb, "210987654321") {
		t.Errorf("response body still contains a real account ID: %s", rb)
	}
}

func TestRecordClient_Constructs(t *testing.T) {
	// Construction only — recording does real I/O and is never run in CI.
	if c := RecordClient(t, t.TempDir()+"/new_cassette", nil); c == nil {
		t.Fatal("RecordClient returned nil client")
	}
}

// checkScrubbed asserts a string contains none of the secret/PII patterns the
// WU-0.3 fixture gate forbids (reusing the redaction regexes).
func checkScrubbed(t *testing.T, label, s string) {
	t.Helper()
	if m := reAccessKey.FindString(s); m != "" && !strings.Contains(m, "EXAMPLE") {
		t.Errorf("%s leaks AWS access key %q", label, m)
	}
	for _, m := range reEmail.FindAllString(s, -1) {
		if !exampleDomain.MatchString(m) {
			t.Errorf("%s leaks email %q", label, m)
		}
	}
	for _, m := range reAccountID.FindAllString(s, -1) {
		if m != "000000000000" {
			t.Errorf("%s leaks 12-digit account ID %q", label, m)
		}
	}
}

func TestAWSMatcher(t *testing.T) {
	const iamURL = "https://iam.amazonaws.com/"
	listUsers := cassette.Request{Method: "POST", URL: iamURL, Body: "Action=ListUsers&Version=2010-05-08"}
	dynamo := cassette.Request{
		Method:  "POST",
		URL:     "https://dynamodb.us-east-1.amazonaws.com/",
		Headers: http.Header{"X-Amz-Target": {"DynamoDB_20120810.DescribeTable"}},
		Body:    `{"TableName":"a"}`,
	}

	newReq := func(method, url, body string, target string) *http.Request {
		r, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if target != "" {
			r.Header.Set("X-Amz-Target", target)
		}
		return r
	}

	cases := []struct {
		name string
		req  *http.Request
		rec  cassette.Request
		want bool
	}{
		// Query protocol: same URL, disambiguated by body.
		{"query match", newReq("POST", iamURL, "Action=ListUsers&Version=2010-05-08", ""), listUsers, true},
		{"query body mismatch", newReq("POST", iamURL, "Action=ListRoles&Version=2010-05-08", ""), listUsers, false},
		{"method mismatch", newReq("GET", iamURL, "Action=ListUsers&Version=2010-05-08", ""), listUsers, false},
		{"url mismatch", newReq("POST", "https://iam.amazonaws.com/other", "Action=ListUsers&Version=2010-05-08", ""), listUsers, false},
		// json protocol: same op (X-Amz-Target) on different resources differs
		// only in body, so body must be compared too.
		{"json full match", newReq("POST", dynamo.URL, `{"TableName":"a"}`, "DynamoDB_20120810.DescribeTable"), dynamo, true},
		{"json target mismatch", newReq("POST", dynamo.URL, `{"TableName":"a"}`, "DynamoDB_20120810.Scan"), dynamo, false},
		{"json same-op different resource (body) mismatch", newReq("POST", dynamo.URL, `{"TableName":"b"}`, "DynamoDB_20120810.DescribeTable"), dynamo, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AWSMatcher(tc.req, tc.rec); got != tc.want {
				t.Errorf("AWSMatcher = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAWSMatcherRestoresBody(t *testing.T) {
	const body = "Action=ListUsers&Version=2010-05-08"
	r, err := http.NewRequestWithContext(t.Context(), "POST", "https://iam.amazonaws.com/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = AWSMatcher(r, cassette.Request{Method: "POST", URL: "https://iam.amazonaws.com/", Body: body})
	// The body must still be readable after matching (go-vcr calls the matcher
	// once per interaction against the same request, then sends it on a miss).
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(got) != body {
		t.Errorf("restored body = %q, want %q", got, body)
	}
}

func TestRedactAccessKeyDistinct(t *testing.T) {
	// Distinct real keys must scrub to distinct placeholders (records are keyed
	// on the access key ID); the same key must be stable across calls.
	a := redactAccessKey("AKIAFAKEACCESSKEY001")
	b := redactAccessKey("AKIAFAKEACCESSKEY002")
	if a == b {
		t.Errorf("distinct keys collapsed to the same placeholder: %q", a)
	}
	if a != redactAccessKey("AKIAFAKEACCESSKEY001") {
		t.Error("placeholder is not deterministic")
	}
	for _, p := range []string{a, b} {
		if !strings.Contains(p, "EXAMPLE") {
			t.Errorf("placeholder %q lacks EXAMPLE (fixture gate would flag it)", p)
		}
		if !reAccessKey.MatchString(p) {
			t.Errorf("placeholder %q is not a well-formed AKIA token", p)
		}
	}
}
