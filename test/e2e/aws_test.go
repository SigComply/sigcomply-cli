//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/sigcomply/sigcomply-cli/internal/data_sources/apis/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAWS_Connectivity verifies that we can connect to AWS with the provided credentials.
func TestAWS_Connectivity(t *testing.T) {
	skipIfNoAWS(t)

	ctx := context.Background()
	collector := aws.New()

	err := collector.Init(ctx)
	require.NoError(t, err, "Failed to initialize AWS collector")

	status := collector.Status(ctx)
	assert.True(t, status.Connected, "Should be connected to AWS")
	assert.NotEmpty(t, status.AccountID, "Should have account ID")

	t.Logf("Connected to AWS account: %s", status.AccountID)
}

// TestAWS_EvidenceCollection tests that we can collect evidence from AWS.
func TestAWS_EvidenceCollection(t *testing.T) {
	skipIfNoAWS(t)

	ctx := context.Background()
	collector := aws.New()

	err := collector.Init(ctx)
	require.NoError(t, err)

	result, err := collector.Collect(ctx)
	require.NoError(t, err, "Evidence collection should not fail")

	// Log any errors that occurred during collection
	if result.HasErrors() {
		for _, e := range result.Errors {
			t.Logf("Collection warning: %s - %v", e.Service, e.Error)
		}
	}

	// Should have collected at least some evidence
	assert.NotEmpty(t, result.Evidence, "Should have collected some evidence")

	// Count evidence by type
	typeCounts := make(map[string]int)
	for _, ev := range result.Evidence {
		typeCounts[ev.ResourceType]++
	}

	t.Logf("Collected evidence summary:")
	for resourceType, count := range typeCounts {
		t.Logf("  - %s: %d items", resourceType, count)
	}
}

// TestAWS_FullComplianceFlow tests the complete flow from collection to evaluation.
func TestAWS_FullComplianceFlow(t *testing.T) {
	skipIfNoAWS(t)

	ctx := context.Background()

	// Step 1: Collect evidence
	collector := aws.New()
	require.NoError(t, collector.Init(ctx))

	result, err := collector.Collect(ctx)
	require.NoError(t, err, "Collection should succeed")

	t.Logf("Collected %d evidence items", len(result.Evidence))

	// Step 2: Load SOC2 framework and evaluate
	framework := soc2.New()
	eng := engine.New()

	policies := framework.Policies()
	require.NotEmpty(t, policies, "Framework should have policies")

	for _, policy := range policies {
		err := eng.LoadPolicy(policy.Name, policy.Source)
		require.NoError(t, err, "Should load policy %s", policy.Name)
	}

	// Step 3: Evaluate policies
	policyResults, err := eng.Evaluate(ctx, result.Evidence)
	require.NoError(t, err, "Evaluation should succeed")
	require.NotEmpty(t, policyResults, "Should have policy results")

	// Step 4: Validate results structure
	var passCount, failCount, skipCount int
	for _, pr := range policyResults {
		assert.NotEmpty(t, pr.PolicyID, "PolicyID should not be empty")
		assert.NotEmpty(t, pr.ControlID, "ControlID should not be empty")

		switch pr.Status {
		case evidence.StatusPass:
			passCount++
		case evidence.StatusFail:
			failCount++
		case evidence.StatusSkip:
			skipCount++
		}

		t.Logf("Policy %s (%s): %s - evaluated: %d, failed: %d",
			pr.PolicyID, pr.ControlID, pr.Status,
			pr.ResourcesEvaluated, pr.ResourcesFailed)
	}

	t.Logf("Summary: %d passed, %d failed, %d skipped", passCount, failCount, skipCount)
}

// TestAWS_IAMUserCollection specifically tests IAM user collection.
func TestAWS_IAMUserCollection(t *testing.T) {
	skipIfNoAWS(t)

	ctx := context.Background()
	collector := aws.New()

	err := collector.Init(ctx)
	require.NoError(t, err)

	result, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Filter for IAM users
	var iamUsers []evidence.Evidence
	for _, ev := range result.Evidence {
		if ev.ResourceType == "aws:iam:user" {
			iamUsers = append(iamUsers, ev)
		}
	}

	t.Logf("Found %d IAM users", len(iamUsers))

	// Validate IAM user structure
	for _, ev := range iamUsers {
		var data map[string]interface{}
		err := json.Unmarshal(ev.Data, &data)
		require.NoError(t, err, "Should parse IAM user data")

		// Check required fields exist
		assert.NotNil(t, data["user_name"], "Should have user_name")
		assert.NotNil(t, data["arn"], "Should have arn")

		// Log MFA status
		mfaEnabled, ok := data["mfa_enabled"].(bool)
		if ok {
			t.Logf("  User: %s, MFA: %v", data["user_name"], mfaEnabled)
		}
	}
}

// TestAWS_S3BucketCollection specifically tests S3 bucket collection.
func TestAWS_S3BucketCollection(t *testing.T) {
	skipIfNoAWS(t)

	ctx := context.Background()
	collector := aws.New()

	err := collector.Init(ctx)
	require.NoError(t, err)

	result, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Filter for S3 buckets
	var s3Buckets []evidence.Evidence
	for _, ev := range result.Evidence {
		if ev.ResourceType == "aws:s3:bucket" {
			s3Buckets = append(s3Buckets, ev)
		}
	}

	t.Logf("Found %d S3 buckets", len(s3Buckets))

	// Validate S3 bucket structure
	for _, ev := range s3Buckets {
		var data map[string]interface{}
		err := json.Unmarshal(ev.Data, &data)
		require.NoError(t, err, "Should parse S3 bucket data")

		// Check required fields exist
		assert.NotNil(t, data["name"], "Should have name")

		// Log encryption status
		encrypted, ok := data["encryption_enabled"].(bool)
		if ok {
			t.Logf("  Bucket: %s, Encrypted: %v", data["name"], encrypted)
		}
	}
}

// TestAWS_ExpectedViolations tests that our test resources trigger expected violations.
// This test only runs when E2E_TEST_RESOURCES_CREATED=true.
func TestAWS_ExpectedViolations(t *testing.T) {
	skipIfNoAWS(t)
	skipIfNoTestResources(t)

	ctx := context.Background()

	// Collect evidence
	collector := aws.New()
	require.NoError(t, collector.Init(ctx))

	result, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Find our test user without MFA
	var foundNoMFAUser bool

	for _, ev := range result.Evidence {
		if ev.ResourceType == "aws:iam:user" {
			var data map[string]interface{}
			json.Unmarshal(ev.Data, &data)

			userName, _ := data["user_name"].(string)
			mfaEnabled, _ := data["mfa_enabled"].(bool)

			if userName == "sigcomply-e2e-no-mfa" {
				foundNoMFAUser = true
				assert.False(t, mfaEnabled, "Test user 'sigcomply-e2e-no-mfa' should NOT have MFA")
			}
		}
	}

	assert.True(t, foundNoMFAUser, "Should find test user 'sigcomply-e2e-no-mfa'")

	// Evaluate policies
	framework := soc2.New()
	eng := engine.New()

	for _, policy := range framework.Policies() {
		eng.LoadPolicy(policy.Name, policy.Source)
	}

	policyResults, err := eng.Evaluate(ctx, result.Evidence)
	require.NoError(t, err)

	// Find MFA policy result
	for _, pr := range policyResults {
		if pr.PolicyID == "soc2-cc6.1-mfa" {
			t.Logf("MFA Policy: %s", pr.Status)
			t.Logf("  Resources evaluated: %d", pr.ResourcesEvaluated)
			t.Logf("  Resources failed: %d", pr.ResourcesFailed)

			if foundNoMFAUser {
				assert.Equal(t, evidence.StatusFail, pr.Status,
					"MFA policy should fail because test user without MFA exists")
				assert.GreaterOrEqual(t, pr.ResourcesFailed, 1,
					"Should have at least 1 MFA violation")
			}
			break
		}
	}
}

// TestAWS_EvidenceHashing verifies that evidence hashes are computed correctly.
func TestAWS_EvidenceHashing(t *testing.T) {
	skipIfNoAWS(t)

	ctx := context.Background()
	collector := aws.New()

	require.NoError(t, collector.Init(ctx))

	result, err := collector.Collect(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, result.Evidence)

	// Verify each evidence item has a valid hash
	for _, ev := range result.Evidence {
		assert.NotEmpty(t, ev.Hash, "Evidence should have hash: %s", ev.ResourceID)
		assert.Len(t, ev.Hash, 64, "Hash should be 64 hex chars (SHA-256): %s", ev.ResourceID)

		// Verify hash is valid hex
		for _, c := range ev.Hash {
			assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
				"Hash should be lowercase hex: %s", ev.Hash)
		}
	}

	t.Logf("Verified hashes for %d evidence items", len(result.Evidence))
}
