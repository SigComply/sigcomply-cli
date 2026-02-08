//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestS3Storage_Init verifies that we can initialize the S3 storage backend.
func TestS3Storage_Init(t *testing.T) {
	skipIfNoAWS(t)
	skipIfNoStorage(t)

	ctx := context.Background()

	cfg := &storage.Config{
		Backend: "s3",
		S3: &storage.S3Config{
			Bucket: getEnvOrDefault("SIGCOMPLY_STORAGE_BUCKET", ""),
			Region: getEnvOrDefault("SIGCOMPLY_STORAGE_REGION", "us-east-1"),
			Prefix: fmt.Sprintf("e2e-test-init/%d", time.Now().Unix()),
		},
	}

	backend, err := storage.NewBackend(cfg)
	require.NoError(t, err, "Should create S3 backend")

	err = backend.Init(ctx)
	require.NoError(t, err, "Should initialize S3 backend")

	defer backend.Close()

	assert.Equal(t, "s3", backend.Name(), "Backend name should be s3")
	t.Logf("Successfully initialized S3 storage backend")
}

// TestS3Storage_StoreAndRetrieve tests storing and retrieving evidence from S3.
func TestS3Storage_StoreAndRetrieve(t *testing.T) {
	skipIfNoAWS(t)
	skipIfNoStorage(t)

	ctx := context.Background()
	testPrefix := fmt.Sprintf("e2e-test-store/%d", time.Now().Unix())

	cfg := &storage.Config{
		Backend: "s3",
		S3: &storage.S3Config{
			Bucket: getEnvOrDefault("SIGCOMPLY_STORAGE_BUCKET", ""),
			Region: getEnvOrDefault("SIGCOMPLY_STORAGE_REGION", "us-east-1"),
			Prefix: testPrefix,
		},
	}

	backend, err := storage.NewBackend(cfg)
	require.NoError(t, err)
	require.NoError(t, backend.Init(ctx))
	defer backend.Close()

	// Create test evidence
	testData := []byte(`{"test_field": "test_value", "timestamp": "2024-01-01T00:00:00Z"}`)
	testEvidence := evidence.New("e2e-test", "test:resource", "test-resource-123", testData)

	// Store the evidence
	stored, err := backend.Store(ctx, &testEvidence)
	require.NoError(t, err, "Should store evidence")

	assert.NotEmpty(t, stored.Path, "Stored item should have path")
	assert.NotEmpty(t, stored.Hash, "Stored item should have hash")
	assert.True(t, stored.Size > 0, "Stored item should have size > 0")

	t.Logf("Stored evidence at: %s (size: %d, hash: %s)", stored.Path, stored.Size, stored.Hash)

	// Retrieve the evidence
	retrieved, err := backend.Get(ctx, stored.Path)
	require.NoError(t, err, "Should retrieve evidence")

	assert.Equal(t, testData, retrieved, "Retrieved data should match stored data")
	t.Logf("Successfully retrieved evidence (%d bytes)", len(retrieved))
}

// TestS3Storage_StoreCheckResult tests storing a check result to S3.
func TestS3Storage_StoreCheckResult(t *testing.T) {
	skipIfNoAWS(t)
	skipIfNoStorage(t)

	ctx := context.Background()
	testPrefix := fmt.Sprintf("e2e-test-checkresult/%d", time.Now().Unix())

	cfg := &storage.Config{
		Backend: "s3",
		S3: &storage.S3Config{
			Bucket: getEnvOrDefault("SIGCOMPLY_STORAGE_BUCKET", ""),
			Region: getEnvOrDefault("SIGCOMPLY_STORAGE_REGION", "us-east-1"),
			Prefix: testPrefix,
		},
	}

	backend, err := storage.NewBackend(cfg)
	require.NoError(t, err)
	require.NoError(t, backend.Init(ctx))
	defer backend.Close()

	// Create test check result
	checkResult := &evidence.CheckResult{
		RunID:     uuid.New().String(),
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:           "test-policy",
				ControlID:          "CC1.1",
				Status:             evidence.StatusPass,
				Severity:           evidence.SeverityHigh,
				ResourcesEvaluated: 5,
				ResourcesFailed:    0,
			},
		},
		Environment: evidence.RunEnvironment{
			CI:         true,
			CIProvider: "e2e-test",
			CLIVersion: "test",
		},
	}
	checkResult.CalculateSummary()

	// Store the check result
	stored, err := backend.StoreCheckResult(ctx, checkResult)
	require.NoError(t, err, "Should store check result")

	assert.NotEmpty(t, stored.Path, "Stored item should have path")
	assert.Contains(t, stored.Path, checkResult.RunID, "Path should contain run ID")

	t.Logf("Stored check result at: %s", stored.Path)

	// Retrieve and verify
	retrieved, err := backend.Get(ctx, stored.Path)
	require.NoError(t, err, "Should retrieve check result")
	assert.NotEmpty(t, retrieved, "Retrieved data should not be empty")

	t.Logf("Successfully stored and retrieved check result (%d bytes)", len(retrieved))
}

// TestS3Storage_List tests listing stored items from S3.
func TestS3Storage_List(t *testing.T) {
	skipIfNoAWS(t)
	skipIfNoStorage(t)

	ctx := context.Background()
	testPrefix := fmt.Sprintf("e2e-test-list/%d", time.Now().Unix())

	cfg := &storage.Config{
		Backend: "s3",
		S3: &storage.S3Config{
			Bucket: getEnvOrDefault("SIGCOMPLY_STORAGE_BUCKET", ""),
			Region: getEnvOrDefault("SIGCOMPLY_STORAGE_REGION", "us-east-1"),
			Prefix: testPrefix,
		},
	}

	backend, err := storage.NewBackend(cfg)
	require.NoError(t, err)
	require.NoError(t, backend.Init(ctx))
	defer backend.Close()

	// Store multiple evidence items
	for i := 0; i < 3; i++ {
		testData := []byte(fmt.Sprintf(`{"index": %d}`, i))
		ev := evidence.New("e2e-test", "test:resource", fmt.Sprintf("item-%d", i), testData)
		_, err := backend.Store(ctx, &ev)
		require.NoError(t, err)
	}

	// List all items
	items, err := backend.List(ctx, nil)
	require.NoError(t, err, "Should list items")

	assert.GreaterOrEqual(t, len(items), 3, "Should have at least 3 items")

	t.Logf("Listed %d items:", len(items))
	for _, item := range items {
		t.Logf("  - %s (size: %d)", item.Path, item.Size)
	}
}

// TestS3Storage_Manifest tests creating and loading a storage manifest.
func TestS3Storage_Manifest(t *testing.T) {
	skipIfNoAWS(t)
	skipIfNoStorage(t)

	ctx := context.Background()
	testPrefix := fmt.Sprintf("e2e-test-manifest/%d", time.Now().Unix())

	cfg := &storage.Config{
		Backend: "s3",
		S3: &storage.S3Config{
			Bucket: getEnvOrDefault("SIGCOMPLY_STORAGE_BUCKET", ""),
			Region: getEnvOrDefault("SIGCOMPLY_STORAGE_REGION", "us-east-1"),
			Prefix: testPrefix,
		},
	}

	backend, err := storage.NewBackend(cfg)
	require.NoError(t, err)
	require.NoError(t, backend.Init(ctx))
	defer backend.Close()

	// Create test check result and evidence
	runID := uuid.New().String()
	checkResult := &evidence.CheckResult{
		RunID:     runID,
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:  "test-policy",
				ControlID: "CC1.1",
				Status:    evidence.StatusPass,
			},
		},
	}
	checkResult.CalculateSummary()

	evidenceList := []evidence.Evidence{
		evidence.New("e2e-test", "test:resource", "res-1", []byte(`{"data": 1}`)),
		evidence.New("e2e-test", "test:resource", "res-2", []byte(`{"data": 2}`)),
	}

	// Store the complete run
	manifest, err := storage.StoreRun(ctx, backend, checkResult, evidenceList)
	require.NoError(t, err, "Should store run")

	assert.Equal(t, runID, manifest.RunID, "Manifest should have correct run ID")
	assert.Equal(t, "soc2", manifest.Framework, "Manifest should have correct framework")
	assert.Equal(t, 2, manifest.EvidenceCount, "Manifest should have correct evidence count")
	assert.NotEmpty(t, manifest.CheckResult, "Manifest should have check result path")

	t.Logf("Created manifest for run %s:", runID)
	t.Logf("  - Evidence count: %d", manifest.EvidenceCount)
	t.Logf("  - Total size: %d bytes", manifest.TotalSize)
	t.Logf("  - Check result: %s", manifest.CheckResult)

	// Load the manifest back
	loaded, err := storage.LoadManifest(ctx, backend, runID)
	require.NoError(t, err, "Should load manifest")

	assert.Equal(t, manifest.RunID, loaded.RunID, "Loaded manifest should match")
	assert.Equal(t, manifest.EvidenceCount, loaded.EvidenceCount, "Evidence count should match")

	t.Logf("Successfully loaded manifest for run %s", runID)
}
