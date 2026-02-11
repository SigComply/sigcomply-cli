//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

func runScenario(t *testing.T, cfg *E2EConfig, allCreds []*ResolvedCredentials, scenario *Scenario) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	secret := cfg.ResolveHMACSecret()

	providers := make([]string, len(allCreds))
	for i, c := range allCreds {
		providers[i] = c.Provider
	}
	t.Logf("Scenario: %s | Framework: %s | Providers: %s",
		scenario.Name, scenario.Framework, strings.Join(providers, ", "))

	// ===== Phase 1: Collect Evidence =====
	var evidenceList []evidence.Evidence

	t.Run("collect-evidence", func(t *testing.T) {
		for _, creds := range allCreds {
			collected, err := collectEvidence(t, ctx, creds, scenario)
			require.NoError(t, err, "Evidence collection failed for provider %s", creds.Provider)
			evidenceList = append(evidenceList, collected...)
		}
	})

	// Ensure non-nil for downstream phases (may be empty for negative tests)
	if evidenceList == nil {
		evidenceList = []evidence.Evidence{}
	}

	// For positive scenarios, abort early if nothing was collected
	if !scenario.Assertions.CollectionErrorsExpected && len(evidenceList) == 0 {
		t.Fatal("No evidence collected and errors were not expected — aborting remaining phases")
	}

	if len(evidenceList) == 0 {
		t.Log("Zero evidence collected — policies will evaluate with empty input (expect all skip)")
	}

	// ===== Phase 2: Evaluate Policies =====
	var policyResults []evidence.PolicyResult

	t.Run("evaluate-policies", func(t *testing.T) {
		framework := resolveFramework(scenario.Framework)
		require.NotNil(t, framework, "Unknown framework: %s", scenario.Framework)

		eng := engine.New()

		policies := framework.Policies()
		require.NotEmpty(t, policies, "Framework has no policies")

		for _, p := range policies {
			err := eng.LoadPolicy(p.Name, p.Source)
			require.NoError(t, err, "Failed to load policy %s", p.Name)
		}

		var evalErr error
		policyResults, evalErr = eng.Evaluate(ctx, evidenceList)
		require.NoError(t, evalErr, "Policy evaluation failed")
		require.NotEmpty(t, policyResults, "No policy results produced")

		for _, pr := range policyResults {
			assert.True(t, pr.Status.IsValid(),
				"Invalid result status for policy %s: %s", pr.PolicyID, pr.Status)
			t.Logf("Policy %s (control %s): status=%s evaluated=%d violations=%d",
				pr.PolicyID, pr.ControlID, pr.Status, pr.ResourcesEvaluated, len(pr.Violations))
		}

		// Check expected policy results if specified
		if len(scenario.Assertions.ExpectedPolicyResults) > 0 {
			resultMap := make(map[string]evidence.ResultStatus)
			for _, pr := range policyResults {
				resultMap[pr.PolicyID] = pr.Status
			}

			for policyID, expectedStatus := range scenario.Assertions.ExpectedPolicyResults {
				actual, ok := resultMap[policyID]
				require.True(t, ok, "Expected policy %s not found in results", policyID)
				assert.Equal(t, evidence.ResultStatus(expectedStatus), actual,
					"Policy %s: expected %s, got %s", policyID, expectedStatus, actual)
			}
		}
	})

	if policyResults == nil {
		policyResults = []evidence.PolicyResult{}
	}

	// ===== Phase 3: Hash Results =====
	runID := uuid.New().String()
	checkResult := &evidence.CheckResult{
		RunID:         runID,
		Framework:     scenario.Framework,
		Timestamp:     time.Now().UTC(),
		PolicyResults: policyResults,
	}
	checkResult.CalculateSummary()

	var hashes *attestation.EvidenceHashes

	t.Run("hash-results", func(t *testing.T) {
		var hashErr error
		hashes, hashErr = attestation.ComputeEvidenceHashes(checkResult, evidenceList)
		require.NoError(t, hashErr, "ComputeEvidenceHashes failed")
		require.NotEmpty(t, hashes.CheckResult, "CheckResult hash is empty")
		require.NotEmpty(t, hashes.Combined, "Combined hash is empty")

		t.Logf("Combined hash: %s", hashes.Combined)
		t.Logf("Evidence hashes: %d items", len(hashes.Evidence))
	})

	if hashes == nil {
		t.Fatal("Hashing failed — aborting remaining phases")
	}

	// ===== Phase 4: Sign Attestation =====
	att := &attestation.Attestation{
		ID:        uuid.New().String(),
		RunID:     runID,
		Framework: scenario.Framework,
		Timestamp: time.Now().UTC(),
		Hashes:    *hashes,
	}

	t.Run("sign-attestation", func(t *testing.T) {
		signer := attestation.NewHMACSigner(secret)
		err := signer.Sign(att)
		require.NoError(t, err, "HMAC signing failed")
		require.NotEmpty(t, att.Signature.Value, "Signature value is empty")
		assert.Equal(t, attestation.AlgorithmHMACSHA256, att.Signature.Algorithm)

		// Round-trip verify
		verifier := attestation.NewHMACVerifier(secret)
		err = verifier.Verify(att)
		require.NoError(t, err, "HMAC verification failed")

		t.Logf("Attestation signed and verified (algorithm=%s)", att.Signature.Algorithm)
	})

	// ===== Phase 5 & 6: Store and Verify S3 (only if storage configured) =====
	if scenario.Storage == "" {
		t.Log("Skipping storage/S3 phases (no storage profile configured for this scenario)")
		return
	}

	resolvedStorage, err := cfg.ResolveStorage(scenario.Storage)
	if err != nil {
		t.Fatalf("Failed to resolve storage profile %q: %v", scenario.Storage, err)
	}

	bucket := resolvedStorage.Config["bucket"]
	storageRegion := resolvedStorage.Config["region"]
	if storageRegion == "" {
		storageRegion = "us-east-1"
	}
	prefix := testPrefix(scenario.Name)

	// Create S3 client for verification/cleanup (uses credentials set by applyCredentials)
	s3Client := newS3Client(t, storageRegion)

	// Register cleanup — runs even on failure/panic (unless cleanup is disabled)
	registerCleanup(t, cfg, scenario, func() {
		cleanupS3Prefix(t, s3Client, bucket, prefix)
	})

	var manifest *storage.Manifest

	t.Run("store-evidence-s3", func(t *testing.T) {
		storageCfg := &storage.Config{
			Backend: "s3",
			S3: &storage.S3Config{
				Bucket: bucket,
				Region: storageRegion,
				Prefix: prefix,
			},
		}

		backend, err := storage.NewBackend(storageCfg)
		require.NoError(t, err, "NewBackend failed")

		err = backend.Init(ctx)
		require.NoError(t, err, "Storage backend Init failed")
		defer backend.Close() //nolint:errcheck

		manifest, err = storage.StoreRun(ctx, backend, checkResult, evidenceList)
		require.NoError(t, err, "StoreRun failed")
		require.NotNil(t, manifest, "Manifest is nil")

		assert.Equal(t, runID, manifest.RunID)
		assert.Equal(t, scenario.Framework, manifest.Framework)
		assert.Equal(t, len(evidenceList), manifest.EvidenceCount)

		t.Logf("Stored %d evidence items, manifest run_id=%s", manifest.EvidenceCount, manifest.RunID)
		for _, item := range manifest.Items {
			t.Logf("  -> %s (%d bytes)", item.Path, item.Size)
		}
	})

	// ===== Phase 6: Verify S3 Objects =====
	t.Run("verify-s3-objects", func(t *testing.T) {
		verifyS3Objects(t, s3Client, bucket, prefix)
	})
}
