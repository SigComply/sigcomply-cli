//go:build e2e

// Package pipeline provides the E2E test scenario orchestration.
package pipeline

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
	corestorage "github.com/sigcomply/sigcomply-cli/internal/core/storage"
	"github.com/sigcomply/sigcomply-cli/test/e2e/collectors"
	"github.com/sigcomply/sigcomply-cli/test/e2e/config"
	"github.com/sigcomply/sigcomply-cli/test/e2e/frameworks"
	e2estorage "github.com/sigcomply/sigcomply-cli/test/e2e/storage"
)

// RunScenario runs the full compliance pipeline for one scenario:
// collect -> evaluate -> hash -> sign -> store -> verify.
func RunScenario(t *testing.T, cfg *config.E2EConfig, allCreds []*config.ResolvedCredentials, scenario *config.Scenario) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	secret := cfg.ResolveHMACSecret()

	providers := make([]string, len(allCreds))
	for i, c := range allCreds {
		providers[i] = c.Provider
	}
	t.Logf("Scenario: %s | Framework: %s | Providers: %s",
		scenario.Name, scenario.Framework, strings.Join(providers, ", "))

	// Build collector filter map from scenario config.
	// nil map means collect everything; non-nil means only collect from specified providers.
	var collectorFilters map[string][]string
	if len(scenario.Collectors) > 0 {
		collectorFilters = make(map[string][]string)
		for _, cf := range scenario.Collectors {
			collectorFilters[cf.Provider] = cf.Services // nil services = all services for that provider
		}
	}

	// ===== Phase 1: Collect Evidence =====
	var evidenceList []evidence.Evidence

	t.Run("collect-evidence", func(t *testing.T) {
		for _, creds := range allCreds {
			// If filters are set, skip providers not in the filter list
			if collectorFilters != nil {
				if _, ok := collectorFilters[creds.Provider]; !ok {
					t.Logf("Skipping provider %s (not in collector filters)", creds.Provider)
					continue
				}
			}

			collector, err := collectors.Get(creds.Provider)
			if err != nil {
				t.Fatalf("No collector for provider %q: %v", creds.Provider, err)
			}

			err = collector.Init(ctx, t, creds)
			require.NoError(t, err, "Collector init failed for provider %s", creds.Provider)

			// Get service filter for this provider (nil = all services)
			var services []string
			if collectorFilters != nil {
				services = collectorFilters[creds.Provider]
			}

			result, collectErr := collector.Collect(ctx, t, services)
			require.NoError(t, collectErr, "Evidence collection failed for provider %s", creds.Provider)

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

			evidenceList = append(evidenceList, result.Evidence...)

			// Always require evidence for positive scenarios
			if !scenario.Assertions.CollectionErrorsExpected {
				require.NotEmpty(t, result.Evidence, "No evidence collected from provider %s", creds.Provider)
			}

			t.Logf("Collected %d evidence items from %s", len(result.Evidence), creds.Provider)
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
		framework := frameworks.Resolve(scenario.Framework)
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

		// Apply policy filtering if configured
		if scenario.Policies != nil {
			var include, exclude []string
			if scenario.Policies != nil {
				include = scenario.Policies.Include
				exclude = scenario.Policies.Exclude
			}
			policyResults = frameworks.FilterResults(policyResults, include, exclude)
		}

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

	// ===== Phase 3-6: Store, Hash, Sign, Store Attestation (only if storage configured) =====
	runID := uuid.New().String()
	checkResult := &evidence.CheckResult{
		RunID:         runID,
		Framework:     scenario.Framework,
		Timestamp:     time.Now().UTC(),
		PolicyResults: policyResults,
	}
	checkResult.CalculateSummary()

	if scenario.Storage == "" {
		t.Log("Skipping storage/hash/sign phases (no storage profile configured for this scenario)")
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
	prefix := e2estorage.TestPrefix(scenario.Name)

	// Create S3 client for verification/cleanup (uses credentials set by ApplyCredentials)
	s3Client := e2estorage.NewS3Client(t, storageRegion)

	// Register cleanup — runs even on failure/panic (unless cleanup is disabled)
	config.RegisterCleanup(t, cfg, scenario, func() {
		e2estorage.CleanupS3Prefix(t, s3Client, bucket, prefix)
	})

	var manifest *corestorage.Manifest

	// Phase 3: Store evidence (no attestation yet)
	t.Run("store-evidence-s3", func(t *testing.T) {
		storageCfg := &corestorage.Config{
			Backend: "s3",
			S3: &corestorage.S3Config{
				Bucket: bucket,
				Region: storageRegion,
				Prefix: prefix,
			},
		}

		backend, storageErr := corestorage.NewBackend(storageCfg)
		require.NoError(t, storageErr, "NewBackend failed")

		storageErr = backend.Init(ctx)
		require.NoError(t, storageErr, "Storage backend Init failed")
		defer backend.Close() //nolint:errcheck

		manifest, storageErr = corestorage.StoreRun(ctx, backend, checkResult, evidenceList)
		require.NoError(t, storageErr, "StoreRun failed")
		require.NotNil(t, manifest, "Manifest is nil")

		assert.Equal(t, runID, manifest.RunID)
		assert.Equal(t, scenario.Framework, manifest.Framework)
		assert.Greater(t, manifest.EvidenceCount, 0, "No evidence items stored")

		t.Logf("Stored %d evidence items, manifest run_id=%s", manifest.EvidenceCount, manifest.RunID)
		for _, item := range manifest.Items {
			t.Logf("  -> %s (%d bytes)", item.Path, item.Size)
		}
	})

	if manifest == nil {
		t.Fatal("Storage failed — aborting remaining phases")
	}

	// Phase 4: Hash stored files
	var hashes *attestation.EvidenceHashes

	t.Run("hash-stored-files", func(t *testing.T) {
		runPath := corestorage.NewRunPath(checkResult.Framework, checkResult.Timestamp)
		checkResultHash, fileHashes := manifest.FileHashes(runPath.BasePath())
		hashes = attestation.ComputeStoredFileHashes(checkResultHash, fileHashes)
		require.NotEmpty(t, hashes.CheckResult, "CheckResult hash is empty")
		require.NotEmpty(t, hashes.Combined, "Combined hash is empty")

		t.Logf("Combined hash: %s", hashes.Combined)
		t.Logf("Stored file hashes: %d items", len(hashes.StoredFiles))
	})

	// Phase 5: Sign attestation
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

	// Phase 6: Store attestation separately
	t.Run("store-attestation-s3", func(t *testing.T) {
		storageCfg := &corestorage.Config{
			Backend: "s3",
			S3: &corestorage.S3Config{
				Bucket: bucket,
				Region: storageRegion,
				Prefix: prefix,
			},
		}

		backend, storageErr := corestorage.NewBackend(storageCfg)
		require.NoError(t, storageErr, "NewBackend failed")

		storageErr = backend.Init(ctx)
		require.NoError(t, storageErr, "Storage backend Init failed")
		defer backend.Close() //nolint:errcheck

		runPath := corestorage.NewRunPath(checkResult.Framework, checkResult.Timestamp)
		attItem, storageErr := corestorage.StoreAttestation(ctx, backend, *runPath, att)
		require.NoError(t, storageErr, "StoreAttestation failed")
		require.NotNil(t, attItem, "Attestation StoredItem is nil")

		t.Logf("Stored attestation at %s (%d bytes)", attItem.Path, attItem.Size)
	})

	// ===== Phase 6: Verify S3 Objects =====
	t.Run("verify-s3-objects", func(t *testing.T) {
		e2estorage.VerifyS3Objects(t, s3Client, bucket, prefix)
	})
}
