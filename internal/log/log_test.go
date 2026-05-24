package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedact_Email(t *testing.T) {
	in := "user alice@acme.com failed"
	got := Redact(in)
	if !strings.Contains(got, "<redacted:email>") || strings.Contains(got, "alice@acme.com") {
		t.Errorf("Redact(%q) = %q; want email redacted", in, got)
	}
}

func TestRedact_ARN(t *testing.T) {
	in := "policy arn:aws:iam::123456789012:user/alice attached"
	got := Redact(in)
	if !strings.Contains(got, "<redacted:arn>") {
		t.Errorf("Redact(%q) = %q; want arn redacted", in, got)
	}
}

func TestRedact_UUID(t *testing.T) {
	in := "run a3f8b2c1-9d4e-4b23-8f7a-1e5c2d8a9b0f started"
	got := Redact(in)
	if !strings.Contains(got, "<redacted:uuid>") {
		t.Errorf("Redact(%q) = %q; want uuid redacted", in, got)
	}
}

func TestRedact_AWSKey(t *testing.T) {
	cases := []string{
		"key AKIAIOSFODNN7EXAMPLE used",
		"creds ASIAIOSFODNN7EXAMPLE used",
	}
	for _, in := range cases {
		got := Redact(in)
		if !strings.Contains(got, "<redacted:aws-key>") {
			t.Errorf("Redact(%q) = %q; want aws-key redacted", in, got)
		}
	}
}

func TestRedact_JWT(t *testing.T) {
	in := "auth eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4eHgifQ.signature returned"
	got := Redact(in)
	if !strings.Contains(got, "<redacted:token>") {
		t.Errorf("Redact(%q) = %q; want token redacted", in, got)
	}
}

func TestRedact_PassThroughBenignText(t *testing.T) {
	in := "policy soc2.cc6.1.mfa_enforced passed"
	got := Redact(in)
	if got != in {
		t.Errorf("Redact(%q) = %q; want unchanged", in, got)
	}
}

func TestLogger_RedactsAtBoundary(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, false)
	l.Infof("user %s failed", "alice@acme.com")
	out := buf.String()
	if !strings.Contains(out, "<redacted:email>") {
		t.Errorf("logger did not redact email; got %q", out)
	}
	if strings.Contains(out, "alice@acme.com") {
		t.Errorf("email leaked through logger; got %q", out)
	}
}

func TestLogger_DebugSuppressedWhenNotVerbose(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, false)
	l.Debugf("noisy detail")
	if buf.Len() != 0 {
		t.Errorf("debug not suppressed; got %q", buf.String())
	}
}

func TestLogger_DebugEmittedWhenVerbose(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, true)
	l.Debugf("noisy detail")
	if !strings.Contains(buf.String(), "noisy detail") {
		t.Errorf("verbose logger dropped debug; got %q", buf.String())
	}
}

func TestLogger_LevelLabels(t *testing.T) {
	cases := []struct {
		level Level
		emit  func(*Logger)
		want  string
	}{
		{LevelInfo, func(l *Logger) { l.Infof("x") }, "[info]"},
		{LevelWarn, func(l *Logger) { l.Warnf("x") }, "[warn]"},
		{LevelError, func(l *Logger) { l.Errorf("x") }, "[error]"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		l := New(&buf, false)
		c.emit(l)
		if !strings.Contains(buf.String(), c.want) {
			t.Errorf("level %d output %q missing %q", c.level, buf.String(), c.want)
		}
	}
}

func TestDefault_WritesToStderr(t *testing.T) {
	// Default just constructs a logger; we sanity-check it doesn't panic.
	l := Default()
	if l == nil {
		t.Fatal("Default returned nil")
	}
}

func TestNew_NilSinkFallsBackToStderr(t *testing.T) {
	l := New(nil, false)
	if l.sink == nil {
		t.Fatal("nil sink not replaced")
	}
}
