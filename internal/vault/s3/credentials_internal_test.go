package s3

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	testVaultBucket = "vault-bucket"
	testVaultRegion = "us-east-1"
)

// The vault is where every run puts its signed evidence, so a credential
// that cannot be resolved has to surface before collection — not after a
// whole run's work is already done. LoadDefaultConfig succeeds with no
// credentials at all, so only an eager resolve can tell the difference.
func TestNew_MissingCredentialsIsAnError(t *testing.T) {
	stubVaultRetrieve(t, errors.New("no EC2 IMDS role found"))

	_, err := New(context.Background(), Options{Bucket: testVaultBucket, Region: testVaultRegion})
	if err == nil {
		t.Fatal("New with unresolvable credentials = nil error; want an error")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Errorf("New error = %q; want it to name AWS_ACCESS_KEY_ID", err)
	}
}

func TestNew_ResolvedCredentialsSucceed(t *testing.T) {
	stubVaultRetrieve(t, nil)

	v, err := New(context.Background(), Options{Bucket: testVaultBucket, Region: testVaultRegion})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if v.Bucket != testVaultBucket {
		t.Errorf("Bucket = %q; want %q", v.Bucket, testVaultBucket)
	}
}

func stubVaultRetrieve(t *testing.T, err error) {
	t.Helper()
	orig := retrieveCredentials
	t.Cleanup(func() { retrieveCredentials = orig })
	retrieveCredentials = func(context.Context, aws.CredentialsProvider) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIAEXAMPLE"}, err
	}
}
