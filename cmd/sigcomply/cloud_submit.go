package sigcomply

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/cloud"
	"github.com/sigcomply/sigcomply-cli/internal/core/config"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

// sanitizeCheckResultForCloud creates a copy of the check result with status values
// compatible with the Rails API. The Rails API only accepts "pass", "fail", "skip"
// but the CLI also has "error" status. This function maps "error" to "fail".
func sanitizeCheckResultForCloud(result *evidence.CheckResult) *evidence.CheckResult {
	if result == nil {
		return nil
	}

	// Create a shallow copy
	sanitized := *result

	// Deep copy and sanitize policy results
	sanitized.PolicyResults = make([]evidence.PolicyResult, len(result.PolicyResults))
	for i := range result.PolicyResults {
		sanitized.PolicyResults[i] = result.PolicyResults[i]
		// Map "error" status to "fail" for Rails API compatibility
		// Rails only accepts: pass, fail, skip
		if result.PolicyResults[i].Status == evidence.StatusError {
			sanitized.PolicyResults[i].Status = evidence.StatusFail
			// Prepend error indicator to message if not already present
			if result.PolicyResults[i].Message != "" {
				sanitized.PolicyResults[i].Message = "[Error during evaluation] " + result.PolicyResults[i].Message
			} else {
				sanitized.PolicyResults[i].Message = "[Error during evaluation]"
			}
		}
	}

	// Recalculate summary with sanitized statuses
	sanitized.CalculateSummary()

	return &sanitized
}

// buildEvidenceURL constructs a URL for the evidence location.
func buildEvidenceURL(backend, bucket, path string) string {
	switch backend {
	case backendS3:
		if bucket != "" {
			if path != "" {
				return fmt.Sprintf("s3://%s/%s", bucket, path)
			}
			return fmt.Sprintf("s3://%s", bucket)
		}
	case "gcs":
		if bucket != "" {
			if path != "" {
				return fmt.Sprintf("gs://%s/%s", bucket, path)
			}
			return fmt.Sprintf("gs://%s", bucket)
		}
	case backendLocal:
		if path != "" {
			return fmt.Sprintf("file://%s", path)
		}
	}
	return ""
}

// buildAttestation creates a signed attestation from check results and evidence.
func buildAttestation(cfg *config.Config, checkResult *evidence.CheckResult, evidenceList []evidence.Evidence, manifest *storage.Manifest) (*attestation.Attestation, error) {
	// Compute evidence hashes
	hashes, err := attestation.ComputeEvidenceHashes(checkResult, evidenceList)
	if err != nil {
		return nil, fmt.Errorf("failed to compute evidence hashes: %w", err)
	}

	// Add manifest hash if available
	if manifest != nil {
		// Find manifest item in the stored items to get its hash
		for _, item := range manifest.Items {
			if item.Metadata != nil && item.Metadata["type"] == "manifest" {
				hashes.Manifest = item.Hash
				break
			}
		}
	}

	// Build attestation
	att := &attestation.Attestation{
		ID:        uuid.New().String(),
		RunID:     checkResult.RunID,
		Framework: cfg.Framework,
		Timestamp: time.Now(),
		Hashes:    *hashes,
		Environment: attestation.Environment{
			CI:         cfg.CI,
			Provider:   cfg.CIProvider,
			Repository: cfg.Repository,
			Branch:     cfg.Branch,
			CommitSHA:  cfg.CommitSHA,
		},
		CLIVersion: version,
		// PolicyVersions would be populated here once the policy engine
		// supports tracking policy versions/hashes
	}

	// Set storage location
	if cfg.Storage.Enabled {
		att.StorageLocation = attestation.StorageLocation{
			Backend: cfg.Storage.Backend,
			Bucket:  cfg.Storage.Bucket,
			Path:    cfg.Storage.Prefix, // cfg.Storage.Prefix maps to StorageLocation.Path
		}
		if manifest != nil {
			att.StorageLocation.ManifestPath = computeManifestPath(cfg, manifest)
		}
	}

	return att, nil
}

// buildCloudSubmitRequest creates a cloud API submission request.
// The check result is sanitized to ensure status values are compatible with Rails API.
func buildCloudSubmitRequest(cfg *config.Config, checkResult *evidence.CheckResult, att *attestation.Attestation, manifest *storage.Manifest) *cloud.SubmitRequest {
	// Sanitize check result for Rails API compatibility
	// Rails only accepts pass/fail/skip, not error
	sanitizedResult := sanitizeCheckResultForCloud(checkResult)

	req := &cloud.SubmitRequest{
		CheckResult: sanitizedResult,
		Attestation: att,
		RunMetadata: &cloud.RunMetadata{
			CI:         cfg.CI,
			CIProvider: cfg.CIProvider,
			Repository: cfg.Repository,
			Branch:     cfg.Branch,
			CommitSHA:  cfg.CommitSHA,
			CLIVersion: version,
		},
	}

	// Set evidence location based on storage config
	if cfg.Storage.Enabled {
		req.EvidenceLocation = &cloud.EvidenceLocation{
			Backend: cfg.Storage.Backend,
		}

		switch cfg.Storage.Backend {
		case backendS3:
			req.EvidenceLocation.Bucket = cfg.Storage.Bucket
			req.EvidenceLocation.Path = cfg.Storage.Prefix
			req.EvidenceLocation.URL = buildEvidenceURL(backendS3, cfg.Storage.Bucket, cfg.Storage.Prefix)
		case backendLocal:
			req.EvidenceLocation.Path = cfg.Storage.Path
			req.EvidenceLocation.URL = buildEvidenceURL(backendLocal, "", cfg.Storage.Path)
		default:
			req.EvidenceLocation.Path = cfg.Storage.Path
		}

		if manifest != nil {
			req.EvidenceLocation.ManifestPath = computeManifestPath(cfg, manifest)
		}
	}

	return req
}

// computeManifestPath computes the manifest path from the manifest's stored items.
// With the new auditor-friendly layout, the manifest path is stored in the manifest itself.
func computeManifestPath(cfg *config.Config, manifest *storage.Manifest) string {
	// Find the manifest item in stored items (it contains the actual path)
	for _, item := range manifest.Items {
		if item.Metadata != nil && item.Metadata["type"] == "manifest" {
			switch cfg.Storage.Backend {
			case backendS3:
				// S3 paths already include the prefix
				return item.Path
			case backendLocal:
				return cfg.Storage.Path + "/" + item.Path
			default:
				return item.Path
			}
		}
	}

	// Fallback: compute from RunPath
	rp := storage.NewRunPath(manifest.Framework, manifest.Timestamp)
	switch cfg.Storage.Backend {
	case backendS3:
		if cfg.Storage.Prefix != "" {
			return cfg.Storage.Prefix + rp.ManifestPath()
		}
		return rp.ManifestPath()
	case backendLocal:
		return cfg.Storage.Path + "/" + rp.ManifestPath()
	default:
		return rp.ManifestPath()
	}
}

// submitToCloud submits check results to the SigComply Cloud API.
// Returns nil, nil if OIDC authentication is not available.
func submitToCloud(ctx context.Context, cfg *config.Config, checkResult *evidence.CheckResult, evidenceList []evidence.Evidence, manifest *storage.Manifest, baseURL string) (*cloud.SubmitResponse, error) {
	if !cloud.IsOIDCAvailable() {
		return nil, nil
	}

	// Build attestation
	att, err := buildAttestation(cfg, checkResult, evidenceList, manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to build attestation: %w", err)
	}

	return submitToCloudWithAttestation(ctx, cfg, checkResult, manifest, att, baseURL)
}

// submitToCloudWithAttestation submits check results with a pre-built attestation.
// Returns nil, nil if no OIDC authentication is available.
func submitToCloudWithAttestation(ctx context.Context, cfg *config.Config, checkResult *evidence.CheckResult, manifest *storage.Manifest, att *attestation.Attestation, baseURL string) (*cloud.SubmitResponse, error) {
	// Build submission request
	req := buildCloudSubmitRequest(cfg, checkResult, att, manifest)

	// Create cloud client
	client := cloud.NewClient(nil)
	if baseURL != "" {
		client.WithBaseURL(baseURL)
	}

	// Configure OIDC authentication
	if err := cloud.ConfigureClientAuth(ctx, client, nil); err != nil {
		return nil, fmt.Errorf("cloud authentication failed: %w", err)
	}

	// Submit to cloud
	resp, err := client.Submit(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// shouldSubmitToCloud determines whether to submit results to cloud based on OIDC availability and flags.
func shouldSubmitToCloud(_ *config.Config, cloudFlag, noCloudFlag bool) bool {
	// --no-cloud always wins
	if noCloudFlag {
		return false
	}

	// OIDC must be available (CLI only runs in CI with OIDC)
	if !cloud.IsOIDCAvailable() {
		return false
	}

	// --cloud forces submission
	if cloudFlag {
		return true
	}

	// Auto-enable cloud when OIDC is available (CI environment)
	return true
}
