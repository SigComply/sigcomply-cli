// Package awstest is the AWS test seam (WU-2.1): it builds an aws.Config whose
// HTTP traffic is recorded/replayed through a go-vcr cassette, so AWS source
// plugins can be exercised offline through the real SDK deserializer. It pairs
// the AWS-aware cassette matcher (sourcetest.AWSMatcher — AWS query/json
// operations collide on the default method+URL matcher) with deterministic
// replay (dummy static creds, fixed region, no retries).
//
// Service plugins build their client from the returned config, e.g.
//
//	cfg := awstest.ReplayConfig(t, "testdata/cassettes/list_users")
//	client := iam.NewFromConfig(cfg)
//
// For S3, set path-style so recorded URLs stay host-stable across buckets:
//
//	s3.NewFromConfig(awstest.ReplayConfig(t, name), func(o *s3.Options){ o.UsePathStyle = true })
package awstest

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// Region is the fixed region all cassettes are recorded/replayed against;
// endpoint resolution must produce the same host on replay as at record time.
const Region = "us-east-1"

// ReplayConfig returns an aws.Config that replays the named cassette (path
// without the ".yaml" suffix) with no network access, dummy static credentials
// (so SigV4 signing runs without error), the fixed Region, and retries
// disabled for deterministic replay.
func ReplayConfig(t *testing.T, cassetteName string) aws.Config {
	t.Helper()
	client := sourcetest.ReplayClientWithMatcher(t, cassetteName, sourcetest.AWSMatcher)
	return loadConfig(t, client,
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("AKIAEXAMPLE0000000000", "secret", ""),
		),
	)
}

// RecordConfig returns an aws.Config that records real AWS traffic into the
// named cassette (scrubbed by the redaction hook before write), using the
// ambient credential chain (AWS_* env / profile) and the fixed Region. This is
// the maintainer/live path, never the per-PR suite.
func RecordConfig(t *testing.T, cassetteName string) aws.Config {
	t.Helper()
	client := sourcetest.RecordClientWithMatcher(t, cassetteName, http.DefaultTransport, sourcetest.AWSMatcher)
	return loadConfig(t, client)
}

func loadConfig(t *testing.T, httpClient *http.Client, extra ...func(*config.LoadOptions) error) aws.Config {
	t.Helper()
	opts := append([]func(*config.LoadOptions) error{
		config.WithHTTPClient(httpClient),
		config.WithRegion(Region),
		config.WithRetryer(func() aws.Retryer { return aws.NopRetryer{} }),
	}, extra...)
	cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		t.Fatalf("awstest: load config: %v", err)
	}
	return cfg
}
