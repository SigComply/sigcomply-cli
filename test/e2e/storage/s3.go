//go:build e2e

package e2estorage

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigcomply/sigcomply-cli/test/e2e/config"
)

func init() {
	RegisterVerifier("s3", func() Verifier { return &S3Verifier{} })
}

// S3Verifier implements Verifier for S3 storage.
type S3Verifier struct {
	client *s3.Client
	bucket string
	prefix string
	region string
}

// Backend returns "s3".
func (v *S3Verifier) Backend() string { return "s3" }

// Setup initializes the S3 verifier.
func (v *S3Verifier) Setup(t *testing.T, storage *config.ResolvedStorage, prefix string) {
	t.Helper()

	v.bucket = storage.Config["bucket"]
	v.region = storage.Config["region"]
	if v.region == "" {
		v.region = "us-east-1"
	}
	v.prefix = prefix
	v.client = NewS3Client(t, v.region)
}

// Verify checks that evidence and check_result.json files exist in S3.
func (v *S3Verifier) Verify(t *testing.T, _ context.Context) {
	t.Helper()
	VerifyS3Objects(t, v.client, v.bucket, v.prefix)
}

// Cleanup removes all objects under the test prefix.
func (v *S3Verifier) Cleanup(t *testing.T) {
	t.Helper()
	CleanupS3Prefix(t, v.client, v.bucket, v.prefix)
}

// NewS3Client creates a raw AWS S3 client for verification and cleanup.
func NewS3Client(t *testing.T, region string) *s3.Client {
	t.Helper()

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
	)
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	return s3.NewFromConfig(cfg)
}

// CleanupS3Prefix deletes all objects under a prefix in S3.
// Intended for use with t.Cleanup to ensure test artifacts are removed.
func CleanupS3Prefix(t *testing.T, client *s3.Client, bucket, prefix string) {
	t.Helper()
	ctx := context.Background()

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Logf("Warning: failed to list objects for cleanup under %s: %v", prefix, err)
			return
		}

		for _, obj := range page.Contents {
			_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    obj.Key,
			})
			if err != nil {
				t.Logf("Warning: failed to delete object %s: %v", aws.ToString(obj.Key), err)
			}
		}
	}

	t.Logf("Cleaned up S3 prefix: s3://%s/%s", bucket, prefix)
}

// ListS3Objects lists all object keys under a prefix in S3.
func ListS3Objects(t *testing.T, client *s3.Client, bucket, prefix string) []string {
	t.Helper()
	ctx := context.Background()

	var keys []string
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Fatalf("Failed to list S3 objects under %s: %v", prefix, err)
		}

		for _, obj := range page.Contents {
			keys = append(keys, aws.ToString(obj.Key))
		}
	}

	return keys
}

// VerifyS3Objects lists S3 objects under the prefix and asserts that evidence
// and check_result.json files exist.
func VerifyS3Objects(t *testing.T, client *s3.Client, bucket, prefix string) {
	t.Helper()

	keys := ListS3Objects(t, client, bucket, prefix)
	require.NotEmpty(t, keys, "No S3 objects found under prefix %s", prefix)

	var hasEvidence, hasCheckResult bool
	for _, key := range keys {
		relKey := strings.TrimPrefix(key, prefix)
		if strings.HasPrefix(relKey, "evidence/") {
			hasEvidence = true
		}
		if strings.Contains(relKey, "check_result.json") {
			hasCheckResult = true
		}
	}

	assert.True(t, hasEvidence, "No evidence objects found under prefix")
	assert.True(t, hasCheckResult, "No check_result.json found under prefix")

	t.Logf("Verified %d S3 objects under prefix", len(keys))
	for _, key := range keys {
		t.Logf("  -> %s", key)
	}
}
