package storage

import (
	"fmt"
	"strings"
	"time"
)

// RunPath centralizes all path computation for a compliance run.
// It produces human-readable, auditor-friendly paths with no UUIDs.
type RunPath struct {
	Framework string // e.g. "soc2"
	Date      string // "2026-02-14"
}

// NewRunPath creates a RunPath from a framework name and timestamp.
func NewRunPath(framework string, timestamp time.Time) *RunPath {
	return &RunPath{
		Framework: framework,
		Date:      timestamp.UTC().Format("2006-01-02"),
	}
}

// BasePath returns the run-level directory path.
// Example: "runs/soc2/2026-02-14"
func (r *RunPath) BasePath() string {
	return fmt.Sprintf("runs/%s/%s", r.Framework, r.Date)
}

// PolicyDir returns the directory path for a policy within the run.
// It strips the framework prefix from the policy ID to produce a clean slug.
// Example: PolicyDir("soc2-cc6.1-mfa", "soc2") -> "runs/soc2/2026-02-14/cc6.1-mfa"
func (r *RunPath) PolicyDir(policyID, framework string) string {
	slug := PolicySlug(policyID, framework)
	return r.BasePath() + "/" + slug
}

// ManifestPath returns the path to the manifest file.
func (r *RunPath) ManifestPath() string {
	return r.BasePath() + "/manifest.json"
}

// AttestationPath returns the path to the attestation file.
func (r *RunPath) AttestationPath() string {
	return r.BasePath() + "/attestation.json"
}

// CheckResultPath returns the path to the aggregate check result file.
func (r *RunPath) CheckResultPath() string {
	return r.BasePath() + "/check_result.json"
}

// PolicySlug strips the framework prefix from a policy ID to produce a clean folder name.
// Example: "soc2-cc6.1-mfa" with framework "soc2" -> "cc6.1-mfa"
// If the policy ID doesn't start with the framework prefix, it is returned as-is.
func PolicySlug(policyID, framework string) string {
	prefix := framework + "-"
	if strings.HasPrefix(policyID, prefix) {
		return policyID[len(prefix):]
	}
	return policyID
}

// ExtractResourceName extracts a human-readable name from a resource ID (typically an ARN).
// Examples:
//
//	"arn:aws:iam::123456789012:user/alice" -> "alice"
//	"arn:aws:s3:::my-bucket"               -> "my-bucket"
//	"arn:aws:cloudtrail:us-east-1:123:trail/main" -> "main"
//	"john-doe" (non-ARN)                   -> "john-doe"
func ExtractResourceName(resourceID string) string {
	if !strings.HasPrefix(resourceID, "arn:") {
		return resourceID
	}

	// ARN format: arn:partition:service:region:account:resource
	// resource can be: resource-type/resource-id, resource-type:resource-id, or just resource-id
	parts := strings.SplitN(resourceID, ":", 6)
	if len(parts) < 6 {
		return resourceID
	}

	resource := parts[5]

	// Handle resource-type/resource-id (e.g. "user/alice", "trail/main")
	if idx := strings.LastIndex(resource, "/"); idx >= 0 {
		return resource[idx+1:]
	}

	// Handle resource-type:resource-id (e.g. "table:my-table")
	if idx := strings.LastIndex(resource, ":"); idx >= 0 {
		return resource[idx+1:]
	}

	// S3 ARNs: arn:aws:s3:::bucket-name -> resource is "bucket-name" (no / or :)
	return resource
}

// EvidenceDescriptor builds a clean filename prefix from a resource type and resource name.
// It drops the provider prefix and joins service-type-name with dashes.
// Examples:
//
//	"aws:iam:user" + "alice"       -> "iam-user-alice"
//	"aws:s3:bucket" + "my-bucket"  -> "s3-bucket-my-bucket"
//	"github:member" + "john"       -> "member-john"
func EvidenceDescriptor(resourceType, resourceName string) string {
	parts := strings.Split(resourceType, ":")

	// Drop the provider prefix (first part: "aws", "github", etc.)
	if len(parts) > 1 {
		parts = parts[1:]
	}

	// Append the resource name
	parts = append(parts, resourceName)

	return strings.Join(parts, "-")
}

// EvidenceFilename returns the full evidence filename for a given resource.
// Example: EvidenceFilename("aws:iam:user", "arn:aws:iam::123:user/alice") -> "iam-user-alice.json"
func EvidenceFilename(resourceType, resourceID string) string {
	name := ExtractResourceName(resourceID)
	descriptor := EvidenceDescriptor(resourceType, name)
	return descriptor + ".json"
}

// EvidenceTypeFilename returns an aggregated evidence filename for a resource type.
// All resources of this type are stored in a single file as a JSON array.
// Examples:
//
//	"aws:iam:user"           -> "iam-users.json"
//	"aws:s3:bucket"          -> "s3-buckets.json"
//	"aws:cloudtrail:trail"   -> "cloudtrail-trails.json"
//	"github:member"          -> "members.json"
//	"github:repo"            -> "repos.json"
func EvidenceTypeFilename(resourceType string) string {
	parts := strings.Split(resourceType, ":")

	// Drop the provider prefix (first part: "aws", "github", etc.)
	if len(parts) > 1 {
		parts = parts[1:]
	}

	// Pluralize the last part (simple: append "s")
	last := len(parts) - 1
	parts[last] += "s"

	return strings.Join(parts, "-") + ".json"
}
