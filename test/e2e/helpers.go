//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

// providerSDKEnvVars maps credential profile field names to standard SDK
// environment variables for each provider. When a scenario runs, the test
// runner reads the source env var from the profile (e.g. E2E_AWS_ACCESS_KEY_ID)
// and sets the standard SDK env var (e.g. AWS_ACCESS_KEY_ID) via t.Setenv.
//
// To add a new provider: add an entry here and a matching credential profile
// in e2e/config.yaml — no other Go code changes needed.
var providerSDKEnvVars = map[string]map[string]string{
	"aws": {
		"access_key_id":     "AWS_ACCESS_KEY_ID",
		"secret_access_key": "AWS_SECRET_ACCESS_KEY",
		"region":            "AWS_DEFAULT_REGION",
	},
	"github": {
		"token": "GITHUB_TOKEN",
	},
	"gitlab": {
		"token": "GITLAB_TOKEN",
	},
	"gcp": {
		"credentials_file": "GOOGLE_APPLICATION_CREDENTIALS",
		"project":          "GCP_PROJECT",
	},
	"azure": {
		"client_id":       "AZURE_CLIENT_ID",
		"client_secret":   "AZURE_CLIENT_SECRET",
		"tenant_id":       "AZURE_TENANT_ID",
		"subscription_id": "AZURE_SUBSCRIPTION_ID",
	},
}

// applyCredentials sets the standard SDK environment variables for a provider
// using t.Setenv (automatically restored after the test completes).
// This allows each scenario to run with its own credentials without
// cross-contamination — no t.Parallel() needed.
func applyCredentials(t *testing.T, creds *ResolvedCredentials) {
	t.Helper()

	mapping, ok := providerSDKEnvVars[creds.Provider]
	if !ok {
		t.Fatalf("No SDK env var mapping for provider %q — add it to providerSDKEnvVars in helpers.go", creds.Provider)
	}

	for key, value := range creds.Values {
		sdkEnvVar, ok := mapping[key]
		if !ok {
			// Extra fields (e.g. "org" for GitHub) don't map to SDK env vars.
			// They're still available via creds.Values for direct use.
			continue
		}
		t.Setenv(sdkEnvVar, value)
	}
}

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
