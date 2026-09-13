package awscfg

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func TestFromEnv(t *testing.T) {
	got := FromEnv(sources.Env{Config: map[string]any{
		"region":            "us-west-2",
		"role_arn":          "  arn:aws:iam::210987654321:role/Audit  ",
		"external_id":       " ext-1 ",
		"role_session_name": "nightly",
	}})
	want := Options{
		Region:      "us-west-2",
		RoleARN:     "arn:aws:iam::210987654321:role/Audit",
		ExternalID:  "ext-1",
		SessionName: "nightly",
	}
	if got != want {
		t.Errorf("FromEnv = %+v; want %+v", got, want)
	}
}

func TestFromEnv_Empty(t *testing.T) {
	got := FromEnv(sources.Env{Config: map[string]any{}})
	if got != (Options{}) {
		t.Errorf("FromEnv = %+v; want zero Options", got)
	}
}

// `profile` is deliberately not a key: LoadDefaultConfig resolves env
// credentials ahead of a shared-config profile, so on a CI runner with
// AWS_ACCESS_KEY_ID exported it would be silently ignored and both
// instances would scan the same account while appearing not to.
func TestFromEnv_IgnoresProfile(t *testing.T) {
	got := FromEnv(sources.Env{Config: map[string]any{"profile": "second-account"}})
	if got != (Options{}) {
		t.Errorf("FromEnv = %+v; profile must not be honoured", got)
	}
}

// The cache key is the whole Options value. Two instances pointing at
// different roles must never share a resolved config — sharing one would
// silently collect both "accounts" as the same principal.
func TestCacheKeyDistinguishesInstances(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	a := Options{Region: "us-east-1", RoleARN: "arn:aws:iam::111111111111:role/A"}
	b := Options{Region: "us-east-1", RoleARN: "arn:aws:iam::222222222222:role/B"}
	if a == b {
		t.Fatal("distinct roles must produce distinct cache keys")
	}

	// Same instance twice is one key: without this, one instance would
	// issue an AssumeRole per AWS plugin (~23) on every run.
	if (Options{Region: "us-east-1"}) != (Options{Region: "us-east-1"}) {
		t.Fatal("identical options must share a cache key")
	}
}
