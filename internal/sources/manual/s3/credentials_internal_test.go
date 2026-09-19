package s3

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// Config keys the factory reads, mirrored from the external test file.
const (
	keyBucket  = "bucket"
	keyRegion  = "region"
	testRegion = "us-east-1"

	testBucketName  = "evidence"
	testAccessKeyID = "AKIAEXAMPLE"
)

// manual.pdf is a project-level singleton, so a credential that cannot be
// resolved is one configuration error — not a collection error repeated
// across every manual policy in the run. LoadDefaultConfig succeeds with no
// credentials at all, so only an eager resolve can tell the difference.
func TestNew_MissingCredentialsIsAnError(t *testing.T) {
	stub(t, &aws.Credentials{}, errors.New("no EC2 IMDS role found"))

	_, err := New(context.Background(), Options{Bucket: testBucketName, Region: testRegion})
	if err == nil {
		t.Fatal("New with unresolvable credentials = nil error; want an error")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Errorf("New error = %q; want it to name AWS_ACCESS_KEY_ID", err)
	}
}

func TestNew_ResolvedCredentialsSucceed(t *testing.T) {
	stub(t, &aws.Credentials{AccessKeyID: testAccessKeyID}, nil)

	r, err := New(context.Background(), Options{Bucket: testBucketName, Region: testRegion})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if r.Bucket != testBucketName {
		t.Errorf("Bucket = %q; want %q", r.Bucket, testBucketName)
	}
}

func stub(t *testing.T, creds *aws.Credentials, err error) {
	t.Helper()
	orig := retrieveCredentials
	t.Cleanup(func() { retrieveCredentials = orig })
	retrieveCredentials = func(context.Context, aws.CredentialsProvider) (aws.Credentials, error) {
		return *creds, err
	}
}

// --- factory build path -------------------------------------------------
//
// These live in the internal test package because the factory now resolves
// credentials at construction: they need the seam above. Before that they
// passed only because the SDK built a client without authenticating, which
// quietly made them depend on whatever credentials the machine happened to
// have — green on a developer laptop, red in CI.

func TestBuild_DefaultsPrefix(t *testing.T) {
	stub(t, &aws.Credentials{AccessKeyID: testAccessKeyID}, nil)
	f, ok := manual.LookupReader("s3")
	if !ok {
		t.Fatal("s3 reader not registered")
	}
	_, scheme, bucket, prefix, err := f(map[string]any{
		keyBucket: "b",
		keyRegion: testRegion,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if scheme != "s3" {
		t.Errorf("scheme: got %q, want \"s3\"", scheme)
	}
	if bucket != "b" {
		t.Errorf("bucket: got %q, want \"b\"", bucket)
	}
	if prefix != "manual/" {
		t.Errorf("prefix: got %q, want \"manual/\"", prefix)
	}
}

func TestBuild_PassesEndpointAndPathStyle(t *testing.T) {
	stub(t, &aws.Credentials{AccessKeyID: testAccessKeyID}, nil)
	f, ok := manual.LookupReader("s3")
	if !ok {
		t.Fatal("s3 reader not registered")
	}
	_, _, _, _, err := f(map[string]any{
		keyBucket:          "b",
		keyRegion:          testRegion,
		"endpoint":         "https://minio.local:9000",
		"force_path_style": true,
	})
	if err != nil {
		t.Fatalf("build with endpoint + force_path_style: %v", err)
	}
}
