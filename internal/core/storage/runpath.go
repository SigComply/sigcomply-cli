package storage

import (
	"fmt"
	"strings"
	"time"
)

// RunPath centralizes all path computation for a single policy's compliance run folder.
// The policy-first layout groups all artifacts for auditor self-containment:
// each policy folder holds its own evidence (signed envelopes) and result.json.
type RunPath struct {
	framework  string // e.g. "soc2"
	policySlug string // e.g. "cc6.1-mfa"
	timestamp  string // ISO 8601 basic, e.g. "20260214T182049Z"
	runIDShort string // first 8 chars of the run UUID
}

// NewRunPath creates a RunPath for a specific policy within a run.
// policyID is the full policy identifier (e.g. "soc2-cc6.1-mfa"); the framework prefix is stripped.
// runID is the full run UUID; only the first 8 characters are used in the path.
func NewRunPath(framework, policyID, runID string, ts time.Time) *RunPath {
	slug := PolicySlug(policyID, framework)
	t := ts.UTC()

	short := runID
	if len(runID) > 8 {
		short = runID[:8]
	}

	return &RunPath{
		framework:  framework,
		policySlug: slug,
		timestamp:  t.Format("20060102T150405Z"),
		runIDShort: short,
	}
}

// PolicyDir returns the base directory for this policy run.
// Example: "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1"
func (r *RunPath) PolicyDir() string {
	return fmt.Sprintf("%s/%s/%s_%s", r.framework, r.policySlug, r.timestamp, r.runIDShort)
}

// EvidenceDir returns the directory where evidence envelope files are stored.
// Example: "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence"
func (r *RunPath) EvidenceDir() string {
	return r.PolicyDir() + "/evidence"
}

// EvidencePath returns the full path to a named evidence file.
// Example: EvidencePath("iam-users.json") -> "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence/iam-users.json"
func (r *RunPath) EvidencePath(filename string) string {
	return r.EvidenceDir() + "/" + filename
}

// ResultPath returns the path to the per-policy result.json file.
// Example: "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/result.json"
func (r *RunPath) ResultPath() string {
	return r.PolicyDir() + "/result.json"
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
