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
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
	awscollector "github.com/sigcomply/sigcomply-cli/internal/data_sources/apis/aws"
)

// TestE2EFullFlow runs the full compliance pipeline for each enabled scenario:
// collect -> evaluate -> hash -> sign -> store -> verify.
//
// Scenarios run sequentially (not parallel) because each may use different
// credentials via t.Setenv. Scenarios whose credential env vars are missing
// are skipped, not failed — safe for local dev.
func TestE2EFullFlow(t *testing.T) {
	cfg, err := LoadConfig()
	require.NoError(t, err, "Failed to load E2E config")

	scenarios := cfg.EnabledScenarios()
	require.NotEmpty(t, scenarios, "No enabled E2E scenarios found")

	for _, scenario := range scenarios {
		scenario := scenario // capture loop variable
		t.Run(scenario.Name, func(t *testing.T) {
			// Resolve credentials — skip scenario if env vars not set
			creds, err := cfg.ResolveCredentials(scenario.Credentials)
			if err != nil {
				t.Skipf("Skipping %s: %v", scenario.Name, err)
			}

			// Set standard SDK env vars for this scenario's provider.
			// t.Setenv restores original values after the subtest completes.
			applyCredentials(t, creds)

			runScenario(t, cfg, creds, &scenario)
		})
	}
}

// resolveFramework returns the engine.Framework for a given framework name.
func resolveFramework(name string) engine.Framework {
	switch name {
	case "soc2":
		return soc2.New()
	case "iso27001":
		return iso27001.New()
	default:
		return nil
	}
}

func runScenario(t *testing.T, cfg *E2EConfig, creds *ResolvedCredentials, scenario *Scenario) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	secret := cfg.ResolveHMACSecret()
	region := creds.Values["region"]
	if region == "" {
		region = "us-east-1"
	}

	t.Logf("Scenario: %s | Framework: %s | Provider: %s | Region: %s",
		scenario.Name, scenario.Framework, creds.Provider, region)

	// ===== Phase 1: Collect Evidence =====
	var evidenceList []evidence.Evidence

	t.Run("collect-evidence", func(t *testing.T) {
		// Currently only AWS collector is implemented
		require.Equal(t, "aws", creds.Provider, "Only AWS collector is currently supported")

		collector := awscollector.New().WithRegion(region)

		err := collector.Init(ctx)
		require.NoError(t, err, "AWS collector Init failed")

		status := collector.Status(ctx)
		require.True(t, status.Connected, "AWS collector not connected: %s", status.Error)
		t.Logf("Connected to AWS account %s in %s", status.AccountID, status.Region)

		result, err := collector.Collect(ctx)
		require.NoError(t, err, "AWS Collect failed")
		require.NotNil(t, result, "Collection result is nil")

		if scenario.Assertions.CollectionErrorsExpected {
			assert.True(t, result.HasErrors(),
				"Expected collection errors (negative test) but got none")
			for _, e := range result.Errors {
				t.Logf("Expected collection error: service=%s error=%s", e.Service, e.Error)
			}
		} else if result.HasErrors() {
			for _, e := range result.Errors {
				t.Logf("Collection warning: service=%s error=%s", e.Service, e.Error)
			}
		}

		evidenceList = result.Evidence

		// Always require evidence for positive scenarios
		if !scenario.Assertions.CollectionErrorsExpected {
			require.NotEmpty(t, evidenceList, "No evidence collected")
		}

		t.Logf("Collected %d evidence items", len(evidenceList))
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
		storageRegion = region
	}
	prefix := testPrefix(scenario.Name)

	// Create S3 client for verification/cleanup (uses credentials set by applyCredentials)
	s3Client := newS3Client(t, storageRegion)

	// Register cleanup — runs even on failure/panic
	t.Cleanup(func() {
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
		keys := listS3Objects(t, s3Client, bucket, prefix)
		require.NotEmpty(t, keys, "No S3 objects found under prefix %s", prefix)

		var hasEvidence, hasCheckResult bool
		for _, key := range keys {
			relKey := strings.TrimPrefix(key, prefix)
			if strings.HasPrefix(relKey, "evidence/") {
				hasEvidence = true
			}
			if strings.Contains(relKey, "check_result.json") {
				hasCheckResult = true
			}
		}

		assert.True(t, hasEvidence, "No evidence objects found under prefix")
		assert.True(t, hasCheckResult, "No check_result.json found under prefix")

		t.Logf("Verified %d S3 objects under prefix", len(keys))
		for _, key := range keys {
			t.Logf("  -> %s", key)
		}
	})
}
