package log

import (
	"errors"
	"strings"
	"testing"
)

// Tokens a source error can echo back (a GitHub or GitLab 401 body, an
// Okta "SSWS <token>" header in a wrapped request dump) must not reach
// CI logs.
func TestRedact_TokenShapes(t *testing.T) {
	cases := map[string]string{
		"ghp_":        "ghp_" + strings.Repeat("A1b2", 9),
		"gho_":        "gho_" + strings.Repeat("A1b2", 9),
		"ghs_":        "ghs_" + strings.Repeat("A1b2", 9),
		"github_pat_": "github_pat_11ABCDEFG0" + strings.Repeat("a1B2", 15),
		"glpat-":      "glpat-" + strings.Repeat("x1Y2", 5),
		"SSWS":        "SSWS 00" + strings.Repeat("aB3", 13),
	}
	for name, secret := range cases {
		got := Redact("auth failed for token " + secret + " (401)")
		if strings.Contains(got, secret) || strings.Contains(got, secret[len(secret)-12:]) {
			t.Errorf("%s: Redact left the token: %q", name, got)
		}
		if !strings.Contains(got, "<redacted:token>") {
			t.Errorf("%s: Redact = %q; want a <redacted:token> tag", name, got)
		}
	}
	for _, benign := range []string{"ghp is a prefix", "glpat-", "SSWS", "github_pat_ alone"} {
		if got := Redact(benign); got != benign {
			t.Errorf("Redact(%q) = %q; want unchanged", benign, got)
		}
	}
}

// Untrusted text (an API error body, a violation reason built from a
// resource name) is printed by `check` into CI logs. A newline lets it
// start its own line, where "::" is a GitHub Actions workflow command
// (::add-mask::, ::error::, ::stop-commands::) and ANSI escapes can
// hide or rewrite what the reader sees.
func TestSanitize(t *testing.T) {
	hostile := "bucket x\n::error file=a::forged\r##[warning]also\x1b[2K\x1b[1Ahidden\u202eevil\x00\x7f\u0085end"
	got := Sanitize(hostile)
	for _, bad := range []string{"\n", "\r", "\x1b", "\u202e", "\x00", "\x7f", "\u0085", "::", "##["} {
		if strings.Contains(got, bad) {
			t.Errorf("Sanitize left %q in %q", bad, got)
		}
	}
	if !strings.Contains(got, "bucket x") || !strings.Contains(got, "forged") || !strings.HasSuffix(got, "end") {
		t.Errorf("Sanitize dropped readable text: %q", got)
	}
	if plain := "access key AKIA… unused for 120 days — rotate it"; Sanitize(plain) != plain {
		t.Errorf("Sanitize changed plain text: %q", Sanitize(plain))
	}
}

// The logger sanitizes every interpolated value but keeps the newlines
// its own format string asks for.
func TestLogger_SanitizesArguments(t *testing.T) {
	var b strings.Builder
	l := New(&b, false)
	l.Warnf("collector: policy %s: %s", "p1", errors.New("boom\n::add-mask::x"))
	l.Warnf("two lines:\n  %s", "second")
	out := b.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "::") {
			t.Errorf("a logged line starts a workflow command: %q", line)
		}
	}
	if !strings.Contains(out, "two lines:\n  second") {
		t.Errorf("format-string newline lost: %q", out)
	}
}

// Redaction must see an argument before Sanitize breaks up "::", or a
// global or S3 ARN ("arn:aws:iam::123456789012:role/Foo") no longer
// matches the ARN pattern and the account ID reaches the CI log.
func TestLogger_RedactsARNsInArguments(t *testing.T) {
	for _, arn := range []string{
		"arn:aws:iam::123456789012:role/Foo",
		"arn:aws:s3:::my-evidence-bucket",
		"arn:aws:sts::123456789012:assumed-role/Deploy/session",
	} {
		var b strings.Builder
		l := New(&b, false)
		l.Errorf("collector: %v", errors.New("AccessDenied: "+arn+" is not authorized"))
		l.Warnf("resource %s", arn)
		out := b.String()
		for _, leak := range []string{"123456789012", "my-evidence-bucket", "role/Foo"} {
			if strings.Contains(arn, leak) && strings.Contains(out, leak) {
				t.Errorf("logged %q unredacted: %q", leak, out)
			}
		}
		if strings.Count(out, "<redacted:arn>") != 2 {
			t.Errorf("want two <redacted:arn> tags for %s: %q", arn, out)
		}
	}
}

// `check` prints violation reasons that name ARNs; Sanitize keeps the
// "::" of an ARN header so the reader can copy the ARN, while still
// breaking every other "::".
func TestSanitize_KeepsARNsCopyable(t *testing.T) {
	for _, arn := range []string{
		"arn:aws:iam::123456789012:role/Foo",
		"arn:aws:s3:::my-evidence-bucket",
		"arn:aws-us-gov:sts::123456789012:assumed-role/Deploy/s",
	} {
		if got := Sanitize("role " + arn + " has no MFA"); got != "role "+arn+" has no MFA" {
			t.Errorf("Sanitize(%q) = %q; want the ARN unchanged", arn, got)
		}
	}
	for _, hostile := range []string{"::error::x", "arn:aws:iam::x ::add-mask::y", "x::arn:aws:s3:::b", "arn:a:b:::::::stop-commands::t"} {
		got := Sanitize(hostile)
		if strings.HasPrefix(strings.TrimSpace(got), "::") {
			t.Errorf("Sanitize(%q) = %q starts a workflow command", hostile, got)
		}
		rest := arnHeaderRE.ReplaceAllString(got, "")
		if strings.Contains(rest, "::") {
			t.Errorf("Sanitize(%q) = %q left a \"::\" outside an ARN header", hostile, got)
		}
	}
}
