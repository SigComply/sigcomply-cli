package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewRunPath_PolicyDir(t *testing.T) {
	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", "a3f8b2c1-dead-beef-1234-567890abcdef", ts)

	assert.Equal(t, "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1", rp.PolicyDir())
}

func TestRunPath_EvidenceDir(t *testing.T) {
	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", "a3f8b2c1-dead-beef-1234-567890abcdef", ts)

	assert.Equal(t, "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence", rp.EvidenceDir())
}

func TestRunPath_EvidencePath(t *testing.T) {
	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", "a3f8b2c1-dead-beef-1234-567890abcdef", ts)

	assert.Equal(t,
		"soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence/iam-users.json",
		rp.EvidencePath("iam-users.json"),
	)
}

func TestRunPath_ResultPath(t *testing.T) {
	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", "a3f8b2c1-dead-beef-1234-567890abcdef", ts)

	assert.Equal(t,
		"soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/result.json",
		rp.ResultPath(),
	)
}

func TestNewRunPath_RunIDTruncated(t *testing.T) {
	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)

	// Long run ID: only first 8 chars used
	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", "abcdef12-xxxx-xxxx-xxxx-xxxxxxxxxxxx", ts)
	assert.Equal(t, "soc2/cc6.1-mfa/20260214T182049Z_abcdef12", rp.PolicyDir())
}

func TestNewRunPath_ShortRunID(t *testing.T) {
	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)

	// Short run ID: use as-is
	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", "run-123", ts)
	assert.Equal(t, "soc2/cc6.1-mfa/20260214T182049Z_run-123", rp.PolicyDir())
}

func TestNewRunPath_NonUTC(t *testing.T) {
	// Ensure non-UTC times are converted to UTC
	loc := time.FixedZone("EST", -5*3600)
	ts := time.Date(2026, 2, 14, 13, 20, 49, 0, loc) // 13:20 EST = 18:20 UTC
	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", "a3f8b2c1-xxxx", ts)

	assert.Equal(t, "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1", rp.PolicyDir())
}

func TestNewRunPath_MultiplePolicies(t *testing.T) {
	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	runID := "a3f8b2c1-dead-beef-1234-567890abcdef"

	rp1 := NewRunPath("soc2", "soc2-cc6.1-mfa", runID, ts)
	rp2 := NewRunPath("soc2", "soc2-cc6.2-encryption", runID, ts)

	// Same run ID and timestamp, different policy slugs
	assert.Equal(t, "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1", rp1.PolicyDir())
	assert.Equal(t, "soc2/cc6.2-encryption/20260214T182049Z_a3f8b2c1", rp2.PolicyDir())
}

func TestPolicySlug(t *testing.T) {
	tests := []struct {
		policyID  string
		framework string
		expected  string
	}{
		{"soc2-cc6.1-mfa", "soc2", "cc6.1-mfa"},
		{"soc2-cc6.2-encryption", "soc2", "cc6.2-encryption"},
		{"iso27001-a9.2-access", "iso27001", "a9.2-access"},
		{"custom-policy", "soc2", "custom-policy"},               // no prefix match
		{"soc2", "soc2", "soc2"},                                 // exact match, no dash after
		{"soc2-", "soc2", ""},                                    // edge case: just prefix
	}

	for _, tt := range tests {
		t.Run(tt.policyID, func(t *testing.T) {
			result := PolicySlug(tt.policyID, tt.framework)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractResourceName(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		expected   string
	}{
		{"IAM user", "arn:aws:iam::123456789012:user/alice", "alice"},
		{"S3 bucket", "arn:aws:s3:::my-bucket", "my-bucket"},
		{"CloudTrail trail", "arn:aws:cloudtrail:us-east-1:123456789012:trail/main", "main"},
		{"IAM user with path", "arn:aws:iam::123456789012:user/admin/alice", "alice"},
		{"Non-ARN simple", "john-doe", "john-doe"},
		{"Non-ARN with slash", "org/repo", "org/repo"},
		{"Short ARN", "arn:aws:s3", "arn:aws:s3"},
		{"DynamoDB table", "arn:aws:dynamodb:us-east-1:123:table:my-table", "my-table"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractResourceName(tt.resourceID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvidenceDescriptor(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		resourceName string
		expected     string
	}{
		{"AWS IAM user", "aws:iam:user", "alice", "iam-user-alice"},
		{"AWS S3 bucket", "aws:s3:bucket", "my-bucket", "s3-bucket-my-bucket"},
		{"AWS CloudTrail", "aws:cloudtrail:trail", "main", "cloudtrail-trail-main"},
		{"GitHub member", "github:member", "john", "member-john"},
		{"GitHub repo", "github:repo", "my-repo", "repo-my-repo"},
		{"Single part", "custom", "resource", "custom-resource"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EvidenceDescriptor(tt.resourceType, tt.resourceName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvidenceFilename(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		resourceID   string
		expected     string
	}{
		{"IAM user ARN", "aws:iam:user", "arn:aws:iam::123456789012:user/alice", "iam-user-alice.json"},
		{"S3 bucket ARN", "aws:s3:bucket", "arn:aws:s3:::my-bucket", "s3-bucket-my-bucket.json"},
		{"CloudTrail ARN", "aws:cloudtrail:trail", "arn:aws:cloudtrail:us-east-1:123:trail/main", "cloudtrail-trail-main.json"},
		{"GitHub member", "github:member", "john-doe", "member-john-doe.json"},
		{"Simple ID", "aws:iam:user", "bob", "iam-user-bob.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EvidenceFilename(tt.resourceType, tt.resourceID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvidenceTypeFilename(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		expected     string
	}{
		{"AWS IAM user", "aws:iam:user", "iam-users.json"},
		{"AWS S3 bucket", "aws:s3:bucket", "s3-buckets.json"},
		{"AWS CloudTrail trail", "aws:cloudtrail:trail", "cloudtrail-trails.json"},
		{"GitHub member", "github:member", "members.json"},
		{"GitHub repo", "github:repo", "repos.json"},
		{"Single part", "custom", "customs.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EvidenceTypeFilename(tt.resourceType)
			assert.Equal(t, tt.expected, result)
		})
	}
}
