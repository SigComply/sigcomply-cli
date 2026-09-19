package awscfg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// testRegion is the AWS region used by this file's fixtures.
const testRegion = "us-east-1"

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

	a := Options{Region: testRegion, RoleARN: "arn:aws:iam::000000000000:role/A"}
	b := Options{Region: testRegion, RoleARN: "arn:aws:iam::000000000000:role/B"}
	sameAsA := Options{Region: testRegion, RoleARN: "arn:aws:iam::000000000000:role/A"}

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

// stubRetrieve replaces the credential-resolution seam for one test and
// reports how many times Load reached it.
func stubRetrieve(t *testing.T, creds *aws.Credentials, err error) *int {
	t.Helper()
	calls := 0
	orig := retrieveCredentials
	t.Cleanup(func() { retrieveCredentials = orig })
	retrieveCredentials = func(context.Context, aws.CredentialsProvider) (aws.Credentials, error) {
		calls++
		return *creds, err
	}
	return &calls
}

// The ambient path used to be the hole: LoadDefaultConfig succeeds with no
// credentials at all, so a source configured in `sources:` whose credentials
// were never exported failed at the first API call instead of at startup —
// after burning the collector's whole retry budget. `sources:` is the source
// of truth, so an unusable credential is a configuration error, not a
// collection outcome.
func TestLoad_AmbientCredentialsMissingIsAnError(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	stubRetrieve(t, &aws.Credentials{}, errors.New("no EC2 IMDS role found"))

	_, _, err := Load(context.Background(), Options{Region: testRegion})
	if err == nil {
		t.Fatal("Load with unresolvable ambient credentials = nil error; want an error")
	}
	// The message has to tell an operator which knob to turn; "no such
	// host" from three providers down the chain does not.
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") || !strings.Contains(err.Error(), "role_arn") {
		t.Errorf("Load error = %q; want it to name AWS_ACCESS_KEY_ID and role_arn", err)
	}
}

// A failed resolve must not be cached: the RoleARN branch has always
// returned before the cache write, and the ambient branch follows it. A
// cached failure would outlive a mid-run credential refresh.
func TestLoad_FailureIsNotCached(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	calls := stubRetrieve(t, &aws.Credentials{}, errors.New("boom"))

	opts := Options{Region: testRegion}
	for i := 0; i < 2; i++ {
		if _, _, err := Load(context.Background(), opts); err == nil {
			t.Fatalf("call %d: Load = nil error; want an error", i)
		}
	}
	if *calls != 2 {
		t.Errorf("retrieve called %d times; want 2 (a failure must not be cached)", *calls)
	}
	mu.Lock()
	_, hit := cached[opts]
	mu.Unlock()
	if hit {
		t.Error("a failed resolve must leave nothing in the cache")
	}
}

// The success path still memoizes, so 23 AWS plugins sharing one instance
// resolve credentials once rather than 23 times.
func TestLoad_SuccessResolvesOnceAndCaches(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	calls := stubRetrieve(t, &aws.Credentials{AccessKeyID: "AKIAEXAMPLE"}, nil)

	opts := Options{Region: testRegion}
	for i := 0; i < 3; i++ {
		if _, region, err := Load(context.Background(), opts); err != nil || region != testRegion {
			t.Fatalf("call %d: Load = (%q, %v); want (%q, nil)", i, region, err, testRegion)
		}
	}
	if *calls != 1 {
		t.Errorf("retrieve called %d times; want 1 (the resolved config is memoized)", *calls)
	}
}

// The assume-role branch keeps its own message — an operator who set
// role_arn needs to be told the role could not be assumed, not to go
// looking for environment variables.
func TestLoad_AssumeRoleFailureNamesTheRole(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	stubRetrieve(t, &aws.Credentials{}, errors.New("AccessDenied"))

	const roleARN = "arn:aws:iam::210987654321:role/SigComplyAudit"
	_, _, err := Load(context.Background(), Options{Region: testRegion, RoleARN: roleARN})
	if err == nil {
		t.Fatal("Load with an unassumable role = nil error; want an error")
	}
	if !strings.Contains(err.Error(), roleARN) {
		t.Errorf("Load error = %q; want it to name the role %q", err, roleARN)
	}
	if strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Errorf("Load error = %q; the role branch must not send the operator to env vars", err)
	}
}
