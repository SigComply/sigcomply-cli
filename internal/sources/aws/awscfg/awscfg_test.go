package awscfg

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

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
		t.Errorf("FromEnv = %+v; profile must not be honored", got)
	}
}

// The cache key is the whole Options value. Two instances pointing at
// different roles must never share a resolved config — sharing one would
// silently collect both "accounts" as the same principal.
func TestCacheKeyDistinguishesInstances(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	a := Options{Region: "us-east-1", RoleARN: "arn:aws:iam::000000000000:role/A"}
	b := Options{Region: "us-east-1", RoleARN: "arn:aws:iam::000000000000:role/B"}
	sameAsA := Options{Region: "us-east-1", RoleARN: "arn:aws:iam::000000000000:role/A"}

	// Exercise the real cache map rather than comparing literals: what
	// matters is whether one instance can read another's entry.
	mu.Lock()
	cached[a] = aws.Config{Region: "marker-a"}
	_, bHit := cached[b]
	fromSame, sameHit := cached[sameAsA]
	mu.Unlock()

	if bHit {
		t.Error("a different role must not hit another instance's cached credentials")
	}
	// Without reuse, each of the ~23 AWS plugins would assume the role
	// again on every run.
	if !sameHit || fromSame.Region != "marker-a" {
		t.Error("identical options must reuse one cache entry")
	}
}
