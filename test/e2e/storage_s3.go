//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPrefix generates a unique S3 key prefix for a test scenario.
// Format: e2e-test/<scenario>/<timestamp>-<uuid>/
func testPrefix(scenarioName string) string {
	ts := time.Now().UTC().Format("20060102-150405")
	id := uuid.New().String()[:8]
	return fmt.Sprintf("e2e-test/%s/%s-%s/", scenarioName, ts, id)
}

// newS3Client creates a raw AWS S3 client for verification and cleanup.
func newS3Client(t *testing.T, region string) *s3.Client {
	t.Helper()

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
	)
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	return s3.NewFromConfig(cfg)
}

// cleanupS3Prefix deletes all objects under a prefix in S3.
// Intended for use with t.Cleanup to ensure test artifacts are removed.
func cleanupS3Prefix(t *testing.T, client *s3.Client, bucket, prefix string) {
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

// listS3Objects lists all object keys under a prefix in S3.
func listS3Objects(t *testing.T, client *s3.Client, bucket, prefix string) []string {
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

// verifyS3Objects lists S3 objects under the prefix and asserts that evidence
// and check_result.json files exist.
func verifyS3Objects(t *testing.T, client *s3.Client, bucket, prefix string) {
	t.Helper()

	keys := listS3Objects(t, client, bucket, prefix)
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
