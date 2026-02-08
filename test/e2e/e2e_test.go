//go:build e2e

// Package e2e contains end-to-end tests that run against real cloud infrastructure.
// These tests require actual AWS credentials and are not run as part of the normal test suite.
//
// To run E2E tests:
//
//	make test-e2e
//
// Or manually:
//
//	go test -tags=e2e -v ./test/e2e/...
//
// Required environment variables:
//   - AWS_ACCESS_KEY_ID or AWS_ROLE_ARN (for AWS tests)
//   - SIGCOMPLY_STORAGE_BUCKET (for storage tests)
//   - SIGCOMPLY_STORAGE_REGION (for storage tests)
package e2e

import (
	"os"
	"testing"
)

// skipIfNoAWS skips the test if AWS credentials are not configured.
func skipIfNoAWS(t *testing.T) {
	t.Helper()

	// Check for any form of AWS credentials
	hasStaticCreds := os.Getenv("AWS_ACCESS_KEY_ID") != ""
	hasRoleARN := os.Getenv("AWS_ROLE_ARN") != ""
	hasWebIdentity := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != ""

	if !hasStaticCreds && !hasRoleARN && !hasWebIdentity {
		t.Skip("AWS credentials not configured - set AWS_ACCESS_KEY_ID, AWS_ROLE_ARN, or AWS_WEB_IDENTITY_TOKEN_FILE")
	}
}

// skipIfNoStorage skips the test if S3 storage is not configured.
func skipIfNoStorage(t *testing.T) {
	t.Helper()

	if os.Getenv("SIGCOMPLY_STORAGE_BUCKET") == "" {
		t.Skip("S3 storage not configured - set SIGCOMPLY_STORAGE_BUCKET")
	}
}

// skipIfNoTestResources skips the test if E2E test resources haven't been created.
func skipIfNoTestResources(t *testing.T) {
	t.Helper()

	if os.Getenv("E2E_TEST_RESOURCES_CREATED") != "true" {
		t.Skip("E2E test resources not configured - set E2E_TEST_RESOURCES_CREATED=true")
	}
}

// getEnvOrDefault returns the value of an environment variable or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
