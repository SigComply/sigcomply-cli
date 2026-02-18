//nolint:errcheck,goconst // Test file - json.Marshal on known structs won't fail, and policy strings are intentionally duplicated for readability
package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

func TestEngine_New(t *testing.T) {
	eng := New()
	assert.NotNil(t, eng)
}

func TestEngine_LoadPolicy(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-policy",
	"name": "Test Policy",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["test:resource"]
}

violations contains violation if {
	input.resource_type == "test:resource"
	input.data.fail == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Resource is failing"
	}
}
`
	err := eng.LoadPolicy("test-policy", policy)
	require.NoError(t, err)

	// Verify policy was loaded
	policies := eng.GetPolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, "test-policy", policies[0].ID)
	assert.Equal(t, "Test Policy", policies[0].Name)
	assert.Equal(t, "high", string(policies[0].Severity))
	assert.Equal(t, EvalModeIndividual, policies[0].EvaluationMode)
}

func TestEngine_LoadPolicy_InvalidRego(t *testing.T) {
	eng := New()

	err := eng.LoadPolicy("bad-policy", "this is not valid rego")
	assert.Error(t, err)
}

func TestEngine_Evaluate_Individual_Violation(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-mfa",
	"name": "MFA Required",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.mfa_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("User %s does not have MFA enabled", [input.data.user_name])
	}
}
`
	err := eng.LoadPolicy("test-mfa", policy)
	require.NoError(t, err)

	// Create evidence for a user without MFA
	userData := map[string]interface{}{
		"user_name":   "alice",
		"mfa_enabled": false,
	}
	userDataJSON, _ := json.Marshal(userData)

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/alice", userDataJSON),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, "test-mfa", result.PolicyID)
	assert.Equal(t, "TEST.1", result.ControlID)
	assert.Equal(t, evidence.StatusFail, result.Status)
	assert.Equal(t, evidence.SeverityHigh, result.Severity)
	assert.Equal(t, 1, result.ResourcesEvaluated)
	assert.Equal(t, 1, result.ResourcesFailed)
	require.Len(t, result.Violations, 1)
	assert.Contains(t, result.Violations[0].Reason, "alice")
	assert.Contains(t, result.Violations[0].Reason, "MFA")
}

func TestEngine_Evaluate_Individual_Pass(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-mfa",
	"name": "MFA Required",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.mfa_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("User %s does not have MFA enabled", [input.data.user_name])
	}
}
`
	err := eng.LoadPolicy("test-mfa", policy)
	require.NoError(t, err)

	// Create evidence for a user WITH MFA
	userData := map[string]interface{}{
		"user_name":   "bob",
		"mfa_enabled": true,
	}
	userDataJSON, _ := json.Marshal(userData)

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/bob", userDataJSON),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, evidence.StatusPass, result.Status)
	assert.Equal(t, 1, result.ResourcesEvaluated)
	assert.Equal(t, 0, result.ResourcesFailed)
	assert.Empty(t, result.Violations)
}

func TestEngine_Evaluate_MultipleResources(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-mfa",
	"name": "MFA Required",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.mfa_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("User %s does not have MFA enabled", [input.data.user_name])
	}
}
`
	err := eng.LoadPolicy("test-mfa", policy)
	require.NoError(t, err)

	// Create evidence for multiple users
	alice := map[string]interface{}{"user_name": "alice", "mfa_enabled": false}
	bob := map[string]interface{}{"user_name": "bob", "mfa_enabled": true}
	charlie := map[string]interface{}{"user_name": "charlie", "mfa_enabled": false}

	aliceJSON, _ := json.Marshal(alice)
	bobJSON, _ := json.Marshal(bob)
	charlieJSON, _ := json.Marshal(charlie)

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/alice", aliceJSON),
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/bob", bobJSON),
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/charlie", charlieJSON),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, evidence.StatusFail, result.Status)
	assert.Equal(t, 3, result.ResourcesEvaluated)
	assert.Equal(t, 2, result.ResourcesFailed)
	assert.Len(t, result.Violations, 2)
}

func TestEngine_Evaluate_SkipsNonMatchingResources(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-mfa",
	"name": "MFA Required",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.mfa_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No MFA"
	}
}
`
	err := eng.LoadPolicy("test-mfa", policy)
	require.NoError(t, err)

	// Create evidence with mixed resource types
	userData := map[string]interface{}{"user_name": "alice", "mfa_enabled": false}
	bucketData := map[string]interface{}{"name": "my-bucket"}

	userJSON, _ := json.Marshal(userData)
	bucketJSON, _ := json.Marshal(bucketData)

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/alice", userJSON),
		evidence.New("aws", "aws:s3:bucket", "arn:aws:s3:::my-bucket", bucketJSON),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	// Only the IAM user should be evaluated
	assert.Equal(t, 1, result.ResourcesEvaluated)
	assert.Equal(t, 1, result.ResourcesFailed)
}

func TestEngine_Evaluate_Batched(t *testing.T) {
	eng := New()

	// Batched policy: at least one trail must be logging
	policy := `
package sigcomply.test

metadata := {
	"id": "test-logging",
	"name": "Logging Required",
	"framework": "test",
	"control": "TEST.2",
	"severity": "critical",
	"evaluation_mode": "batched",
	"resource_types": ["aws:cloudtrail:trail"]
}

default any_logging := false

any_logging if {
	some i
	input.resources[i].data.is_logging == true
}

violations contains violation if {
	not any_logging
	violation := {
		"resource_id": "account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail is logging"
	}
}
`
	err := eng.LoadPolicy("test-logging", policy)
	require.NoError(t, err)

	// All trails are not logging
	trail1 := map[string]interface{}{"name": "trail1", "is_logging": false}
	trail2 := map[string]interface{}{"name": "trail2", "is_logging": false}

	trail1JSON, _ := json.Marshal(trail1)
	trail2JSON, _ := json.Marshal(trail2)

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:cloudtrail:trail", "arn:aws:cloudtrail:us-east-1:123:trail/trail1", trail1JSON),
		evidence.New("aws", "aws:cloudtrail:trail", "arn:aws:cloudtrail:us-east-1:123:trail/trail2", trail2JSON),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, evidence.StatusFail, result.Status)
	assert.Equal(t, evidence.SeverityCritical, result.Severity)
	assert.Len(t, result.Violations, 1)
}

func TestEngine_Evaluate_Batched_Pass(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-logging",
	"name": "Logging Required",
	"framework": "test",
	"control": "TEST.2",
	"severity": "critical",
	"evaluation_mode": "batched",
	"resource_types": ["aws:cloudtrail:trail"]
}

default any_logging := false

any_logging if {
	some i
	input.resources[i].data.is_logging == true
}

violations contains violation if {
	not any_logging
	violation := {
		"resource_id": "account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail is logging"
	}
}
`
	err := eng.LoadPolicy("test-logging", policy)
	require.NoError(t, err)

	// One trail is logging
	trail1 := map[string]interface{}{"name": "trail1", "is_logging": true}
	trail2 := map[string]interface{}{"name": "trail2", "is_logging": false}

	trail1JSON, _ := json.Marshal(trail1)
	trail2JSON, _ := json.Marshal(trail2)

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:cloudtrail:trail", "arn:aws:cloudtrail:us-east-1:123:trail/trail1", trail1JSON),
		evidence.New("aws", "aws:cloudtrail:trail", "arn:aws:cloudtrail:us-east-1:123:trail/trail2", trail2JSON),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, evidence.StatusPass, result.Status)
	assert.Empty(t, result.Violations)
}

func TestEngine_Evaluate_MultiplePolicies(t *testing.T) {
	eng := New()

	mfaPolicy := `
package sigcomply.mfa

metadata := {
	"id": "test-mfa",
	"name": "MFA Required",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.mfa_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No MFA"
	}
}
`

	encryptionPolicy := `
package sigcomply.encryption

metadata := {
	"id": "test-encryption",
	"name": "Encryption Required",
	"framework": "test",
	"control": "TEST.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"]
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.encryption_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Not encrypted"
	}
}
`

	err := eng.LoadPolicy("test-mfa", mfaPolicy)
	require.NoError(t, err)
	err = eng.LoadPolicy("test-encryption", encryptionPolicy)
	require.NoError(t, err)

	// Create mixed evidence
	userData := map[string]interface{}{"user_name": "alice", "mfa_enabled": false}
	bucketData := map[string]interface{}{"name": "my-bucket", "encryption_enabled": false}

	userJSON, _ := json.Marshal(userData)
	bucketJSON, _ := json.Marshal(bucketData)

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/alice", userJSON),
		evidence.New("aws", "aws:s3:bucket", "arn:aws:s3:::my-bucket", bucketJSON),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// Both policies should fail
	for _, result := range results {
		assert.Equal(t, evidence.StatusFail, result.Status)
		assert.Len(t, result.Violations, 1)
	}
}

// --- Negative tests ---

func TestEngine_LoadPolicy_MissingMetadata(t *testing.T) {
	eng := New()

	// Valid Rego syntax but no metadata rule in sigcomply namespace
	policy := `
package sigcomply.test

violations contains violation if {
	input.data.fail == true
	violation := {"resource_id": "x", "resource_type": "y", "reason": "failed"}
}
`
	err := eng.LoadPolicy("no-metadata", policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata")
}

func TestEngine_Evaluate_EmptyEvidenceList(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-policy",
	"name": "Test Policy",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.data.fail == true
	violation := {"resource_id": "x", "resource_type": "y", "reason": "failed"}
}
`
	err := eng.LoadPolicy("test-policy", policy)
	require.NoError(t, err)

	// Empty evidence list — all policies should be skipped
	results, err := eng.Evaluate(context.Background(), []evidence.Evidence{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, evidence.StatusSkip, results[0].Status)
	assert.Equal(t, 0, results[0].ResourcesEvaluated)
}

func TestEngine_Evaluate_NilEvidenceList(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-policy",
	"name": "Test Policy",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.data.fail == true
	violation := {"resource_id": "x", "resource_type": "y", "reason": "failed"}
}
`
	err := eng.LoadPolicy("test-policy", policy)
	require.NoError(t, err)

	// Nil evidence list — should not panic
	results, err := eng.Evaluate(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, evidence.StatusSkip, results[0].Status)
}

func TestEngine_Evaluate_NoPoliciesLoaded(t *testing.T) {
	eng := New()

	data, _ := json.Marshal(map[string]interface{}{"user_name": "alice"})
	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", data),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestEngine_LoadPolicy_DuplicateID(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-policy",
	"name": "Test Policy",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.data.fail == true
	violation := {"resource_id": "x", "resource_type": "y", "reason": "failed"}
}
`
	err := eng.LoadPolicy("test-policy", policy)
	require.NoError(t, err)

	// Load the same policy again — should not error (appends)
	err = eng.LoadPolicy("test-policy", policy)
	require.NoError(t, err)

	policies := eng.GetPolicies()
	assert.Len(t, policies, 2, "duplicate policies should both be loaded")
}

func TestEngine_Evaluate_CancelledContext(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-policy",
	"name": "Test Policy",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.data.fail == true
	violation := {"resource_id": "x", "resource_type": "y", "reason": "failed"}
}
`
	err := eng.LoadPolicy("test-policy", policy)
	require.NoError(t, err)

	userData, _ := json.Marshal(map[string]interface{}{"fail": true})
	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", userData),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// With a canceled context, Evaluate should not panic and should return results.
	// OPA may complete fast enough to succeed, or it may return an error —
	// we just verify it doesn't crash and returns exactly 1 result.
	results, err := eng.Evaluate(ctx, evidenceList)
	require.NoError(t, err)
	require.Len(t, results, 1)
	// Status could be error (context canceled) or fail (OPA completed fast enough)
	assert.True(t, results[0].Status == evidence.StatusError || results[0].Status == evidence.StatusFail,
		"status should be error or fail, got: %s", results[0].Status)
}

func TestEngine_Evaluate_InvalidEvidenceJSON(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-policy",
	"name": "Test Policy",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.data.fail == true
	violation := {"resource_id": "x", "resource_type": "y", "reason": "failed"}
}
`
	err := eng.LoadPolicy("test-policy", policy)
	require.NoError(t, err)

	// Evidence with invalid JSON data
	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", json.RawMessage(`{invalid json`)),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	require.Len(t, results, 1)
	// Should produce an error result for the policy
	assert.Equal(t, evidence.StatusError, results[0].Status)
}

func TestEngine_GetPolicies_Empty(t *testing.T) {
	eng := New()
	policies := eng.GetPolicies()
	assert.NotNil(t, policies, "GetPolicies should return empty slice, not nil")
	assert.Empty(t, policies)
}

func TestEngine_Evaluate_NoMatchingResources(t *testing.T) {
	eng := New()

	policy := `
package sigcomply.test

metadata := {
	"id": "test-mfa",
	"name": "MFA Required",
	"framework": "test",
	"control": "TEST.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"]
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.mfa_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No MFA"
	}
}
`
	err := eng.LoadPolicy("test-mfa", policy)
	require.NoError(t, err)

	// Only S3 buckets, no IAM users
	bucketData := map[string]interface{}{"name": "my-bucket"}
	bucketJSON, _ := json.Marshal(bucketData)

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:s3:bucket", "arn:aws:s3:::my-bucket", bucketJSON),
	}

	results, err := eng.Evaluate(context.Background(), evidenceList)
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Policy should be skipped when no matching resources
	result := results[0]
	assert.Equal(t, evidence.StatusSkip, result.Status)
	assert.Equal(t, 0, result.ResourcesEvaluated)
}
