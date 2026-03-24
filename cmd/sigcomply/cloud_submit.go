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

// buildAttestation creates a signed attestation from check results and the storage manifest.
// A fresh ephemeral Ed25519 keypair is generated for each call; the private key is discarded
// immediately after signing. The public key and signature are embedded in the returned
// attestation and stored alongside the evidence in the customer's S3 bucket.
func buildAttestation(cfg *config.Config, checkResult *evidence.CheckResult, manifest *storage.Manifest) (*attestation.Attestation, error) {
	// Compute hashes from stored files
	runPath := storage.NewRunPath(checkResult.Framework, checkResult.Timestamp)
	checkResultHash, fileHashes := manifest.FileHashes(runPath.BasePath())
	hashes := attestation.ComputeStoredFileHashes(checkResultHash, fileHashes)

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

	// Set storage location (metadata only — not included in signed payload)
	if cfg.Storage.Enabled {
		att.StorageLocation = attestation.StorageLocation{
			Backend: cfg.Storage.Backend,
			Bucket:  cfg.Storage.Bucket,
			Path:    cfg.Storage.Prefix,
		}
		if manifest != nil {
			att.StorageLocation.ManifestPath = computeManifestPath(cfg, manifest)
		}
	}

	// Sign with an ephemeral Ed25519 keypair. Private key is zeroed immediately after signing.
	signer, err := attestation.NewEd25519Signer()
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation signer: %w", err)
	}
	if err := signer.Sign(att); err != nil {
		return nil, fmt.Errorf("failed to sign attestation: %w", err)
	}

	return att, nil
}

// buildCloudSubmitRequest creates a cloud API submission request containing only aggregated
// policy results. No resource identifiers (ARNs, usernames, emails) are included — only counts.
// The attestation and raw evidence stay entirely in the customer's S3 bucket.
func buildCloudSubmitRequest(cfg *config.Config, checkResult *evidence.CheckResult) *cloud.SubmitRequest {
	// Aggregate policy results: strip violations, keep only counts.
	// Map "error" status to "fail" for Rails API compatibility.
	aggregated := make([]cloud.AggregatedPolicyResult, len(checkResult.PolicyResults))
	for i, pr := range checkResult.PolicyResults {
		status := string(pr.Status)
		if pr.Status == evidence.StatusError {
			// Rails only accepts: pass, fail, skip
			status = string(evidence.StatusFail)
		}
		aggregated[i] = cloud.AggregatedPolicyResult{
			PolicyID:           pr.PolicyID,
			ControlID:          pr.ControlID,
			Status:             status,
			Severity:           string(pr.Severity),
			ResourcesEvaluated: pr.ResourcesEvaluated,
			ResourcesFailed:    pr.ResourcesFailed,
			// NOTE: Violations intentionally excluded — no resource IDs reach the cloud.
		}
	}

	// Build summary, re-counting to reflect error→fail mapping.
	passed, failed, skipped := 0, 0, 0
	for _, r := range aggregated {
		switch r.Status {
		case string(evidence.StatusPass):
			passed++
		case string(evidence.StatusFail):
			failed++
		case string(evidence.StatusSkip):
			skipped++
		}
	}
	total := len(aggregated)
	var score float64
	if total > 0 {
		score = float64(passed) / float64(total)
	}

	return &cloud.SubmitRequest{
		RunID:         checkResult.RunID,
		Framework:     checkResult.Framework,
		Timestamp:     checkResult.Timestamp,
		PolicyResults: aggregated,
		Summary: cloud.AggregatedSummary{
			TotalPolicies:   total,
			PassedPolicies:  passed,
			FailedPolicies:  failed,
			SkippedPolicies: skipped,
			ComplianceScore: score,
		},
		RunMetadata: &cloud.RunMetadata{
			CI:         cfg.CI,
			CIProvider: cfg.CIProvider,
			Repository: cfg.Repository,
			Branch:     cfg.Branch,
			CommitSHA:  cfg.CommitSHA,
			CLIVersion: version,
		},
	}
}

// computeManifestPath computes the manifest path from the manifest's stored items.
func computeManifestPath(cfg *config.Config, manifest *storage.Manifest) string {
	// Find the manifest item in stored items (it contains the actual path)
	for _, item := range manifest.Items {
		if item.Metadata != nil && item.Metadata["type"] == "manifest" {
			switch cfg.Storage.Backend {
			case backendS3:
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

// submitToCloud submits aggregated compliance check results to the SigComply Cloud API.
// Only aggregated policy results are sent — no attestation, no evidence location, no resource IDs.
// Returns nil, nil if OIDC authentication is not available.
func submitToCloud(ctx context.Context, cfg *config.Config, checkResult *evidence.CheckResult, baseURL string) (*cloud.SubmitResponse, error) {
	if !cloud.IsOIDCAvailable() {
		return nil, nil
	}

	req := buildCloudSubmitRequest(cfg, checkResult)

	client := cloud.NewClient(nil)
	if baseURL != "" {
		client.WithBaseURL(baseURL)
	}

	if err := cloud.ConfigureClientAuth(ctx, client, nil); err != nil {
		return nil, fmt.Errorf("cloud authentication failed: %w", err)
	}

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
