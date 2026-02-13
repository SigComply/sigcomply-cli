package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

func TestNewBackend_Local(t *testing.T) {
	cfg := &Config{
		Backend: "local",
		Local: &LocalConfig{
			Path: "/tmp/test-storage",
		},
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)
	assert.Equal(t, "local", backend.Name())
}

func TestNewBackend_LocalDefault(t *testing.T) {
	cfg := &Config{
		Backend: "",
	}

	backend, err := NewBackend(cfg)
	require.NoError(t, err)
	assert.Equal(t, "local", backend.Name())
}

func TestNewBackend_S3MissingConfig(t *testing.T) {
	cfg := &Config{
		Backend: "s3",
	}

	_, err := NewBackend(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "S3 configuration required")
}

func TestNewBackend_UnsupportedBackend(t *testing.T) {
	cfg := &Config{
		Backend: "unknown",
	}

	_, err := NewBackend(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported storage backend")
}

func TestLocalBackend_Init(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "evidence")

	backend := NewLocalBackend(&LocalConfig{Path: storagePath})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	// Verify directory was created
	info, err := os.Stat(storagePath)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestLocalBackend_StoreRaw(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	data := []byte(`[{"resource_id":"alice","data":{"mfa_enabled":true}}]`)
	path := "runs/soc2/2026-02-14/cc6.1-mfa/evidence/iam-users.json"

	item, err := backend.StoreRaw(context.Background(), path, data, map[string]string{
		"resource_type": "aws:iam:user",
		"count":         "1",
	})
	require.NoError(t, err)

	assert.Equal(t, path, item.Path)
	assert.NotEmpty(t, item.Hash)
	assert.Equal(t, int64(len(data)), item.Size)
	assert.Equal(t, "application/json", item.ContentType)
	assert.Equal(t, "aws:iam:user", item.Metadata["resource_type"])

	// Verify file exists on disk
	fullPath := filepath.Join(tmpDir, path)
	_, err = os.Stat(fullPath)
	require.NoError(t, err)
}

func TestLocalBackend_Get(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	// Store data first
	data := []byte(`[{"resource_id":"bob"}]`)
	path := "runs/soc2/2026-02-14/cc6.1-mfa/evidence/iam-users.json"

	_, err = backend.StoreRaw(context.Background(), path, data, nil)
	require.NoError(t, err)

	// Retrieve it
	retrieved, err := backend.Get(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, data, retrieved)
}

func TestLocalBackend_Get_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	_, err = backend.Get(context.Background(), "nonexistent/file.json")
	require.Error(t, err)

	var notFoundErr *NotFoundError
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestLocalBackend_List(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	// Store multiple items
	paths := []string{
		"runs/soc2/2026-02-14/cc6.1-mfa/evidence/iam-users.json",
		"runs/soc2/2026-02-14/cc6.1-mfa/result.json",
		"runs/soc2/2026-02-14/cc6.2-encryption/evidence/s3-buckets.json",
	}
	for _, p := range paths {
		_, err := backend.StoreRaw(context.Background(), p, []byte(`{}`), nil)
		require.NoError(t, err)
	}

	// List all
	items, err := backend.List(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, items, 3)

	// List with prefix
	items, err = backend.List(context.Background(), &ListFilter{Prefix: "runs/soc2/2026-02-14/cc6.1-mfa/evidence"})
	require.NoError(t, err)
	assert.Len(t, items, 1)

	// List with limit
	items, err = backend.List(context.Background(), &ListFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, items, 2)
}

func TestLocalBackend_Close(t *testing.T) {
	backend := NewLocalBackend(&LocalConfig{Path: t.TempDir()})
	err := backend.Close()
	assert.NoError(t, err)
}

func TestStoredItem_JSON(t *testing.T) {
	item := StoredItem{
		Path:        "runs/soc2/2026-02-14/cc6.1-mfa/evidence/iam-users.json",
		Hash:        "abc123",
		Size:        1024,
		StoredAt:    time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		ContentType: "application/json",
		Metadata: map[string]string{
			"resource_type": "aws:iam:user",
		},
	}

	data, err := json.Marshal(item)
	require.NoError(t, err)

	var parsed StoredItem
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, item.Path, parsed.Path)
	assert.Equal(t, item.Hash, parsed.Hash)
}

func TestManifest_JSON(t *testing.T) {
	manifest := Manifest{
		RunID:         "run-123",
		Framework:     "soc2",
		Timestamp:     time.Now(),
		Backend:       "local",
		EvidenceCount: 5,
		TotalSize:     10240,
		Attestation:   "runs/soc2/2026-02-14/attestation.json",
		Items: []StoredItem{
			{Path: "runs/soc2/2026-02-14/cc6.1-mfa/evidence/iam-users.json", Hash: "abc"},
		},
	}

	data, err := json.Marshal(manifest)
	require.NoError(t, err)

	var parsed Manifest
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, manifest.RunID, parsed.RunID)
	assert.Equal(t, manifest.Attestation, parsed.Attestation)
	assert.Len(t, parsed.Items, 1)
}

func TestManifestBuilder_New(t *testing.T) {
	backend := NewLocalBackend(&LocalConfig{Path: t.TempDir()})
	builder := NewManifestBuilder(backend, "soc2")

	manifest := builder.Build()
	assert.Equal(t, "soc2", manifest.Framework)
	assert.Equal(t, "local", manifest.Backend)
}

func TestManifestBuilder_WithRunID(t *testing.T) {
	backend := NewLocalBackend(&LocalConfig{Path: t.TempDir()})
	builder := NewManifestBuilder(backend, "soc2").WithRunID("custom-run-id")

	manifest := builder.Build()
	assert.Equal(t, "custom-run-id", manifest.RunID)
}

func TestManifestBuilder_AddItem(t *testing.T) {
	backend := NewLocalBackend(&LocalConfig{Path: t.TempDir()})
	builder := NewManifestBuilder(backend, "soc2")

	item := &StoredItem{
		Path: "runs/soc2/2026-02-14/cc6.1-mfa/evidence/iam-users.json",
		Hash: "abc123",
		Size: 1024,
	}
	builder.AddItem(item)

	manifest := builder.Build()
	assert.Len(t, manifest.Items, 1)
	assert.Equal(t, int64(1024), manifest.TotalSize)
}

func TestStoreRun_PolicyCentricLayout(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "test-run-123",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:      "soc2-cc6.1-mfa",
				ControlID:     "CC6.1",
				Name:          "MFA Required",
				Status:        evidence.StatusFail,
				Severity:      evidence.SeverityHigh,
				Message:       "1 violation found",
				ResourceTypes: []string{"aws:iam:user"},
				Violations: []evidence.Violation{
					{
						ResourceID:   "arn:aws:iam::123:user/negative",
						ResourceType: "aws:iam:user",
						Reason:       "MFA not enabled",
					},
				},
				ResourcesEvaluated: 2,
				ResourcesFailed:    1,
			},
			{
				PolicyID:      "soc2-cc6.2-encryption",
				ControlID:     "CC6.2",
				Name:          "Encryption Required",
				Status:        evidence.StatusPass,
				Severity:      evidence.SeverityHigh,
				Message:       "All resources compliant",
				ResourceTypes: []string{"aws:s3:bucket"},
				ResourcesEvaluated: 1,
				ResourcesFailed:    0,
			},
		},
	}
	result.CalculateSummary()

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", []byte(`{"name":"alice","mfa":true}`)),
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/negative", []byte(`{"name":"negative","mfa":false}`)),
		evidence.New("aws", "aws:s3:bucket", "arn:aws:s3:::my-bucket", []byte(`{"name":"my-bucket","encrypted":true}`)),
	}

	manifest, err := StoreRun(context.Background(), backend, result, evidenceList, nil)
	require.NoError(t, err)

	assert.Equal(t, "test-run-123", manifest.RunID)
	assert.Equal(t, "soc2", manifest.Framework)

	// Verify policy-centric folder structure exists
	basePath := "runs/soc2/2026-02-14"

	// Check check_result.json at run level
	assert.Equal(t, basePath+"/check_result.json", manifest.CheckResult)
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "check_result.json"))
	require.NoError(t, err)

	// Check manifest.json at run level
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "manifest.json"))
	require.NoError(t, err)

	// Check cc6.1-mfa policy directory — aggregated evidence file
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "cc6.1-mfa", "result.json"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "cc6.1-mfa", "evidence", "iam-users.json"))
	require.NoError(t, err)

	// Verify aggregated evidence contains all users
	evData, err := os.ReadFile(filepath.Join(tmpDir, basePath, "cc6.1-mfa", "evidence", "iam-users.json"))
	require.NoError(t, err)
	var entries []aggregatedEvidenceEntry
	err = json.Unmarshal(evData, &entries)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "Should contain both IAM users in one file")

	// Check cc6.2-encryption policy directory — aggregated evidence file
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "cc6.2-encryption", "result.json"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "cc6.2-encryption", "evidence", "s3-buckets.json"))
	require.NoError(t, err)

	// Verify per-policy result.json content
	resultData, err := os.ReadFile(filepath.Join(tmpDir, basePath, "cc6.1-mfa", "result.json"))
	require.NoError(t, err)

	var storedResult StoredPolicyResult
	err = json.Unmarshal(resultData, &storedResult)
	require.NoError(t, err)

	assert.Equal(t, "soc2-cc6.1-mfa", storedResult.PolicyID)
	assert.Equal(t, evidence.StatusFail, storedResult.Status)
	assert.Equal(t, "MFA Required", storedResult.Name)
	assert.Len(t, storedResult.EvidenceFiles, 1) // One aggregated file, not 2 individual
	assert.Contains(t, storedResult.EvidenceFiles, "evidence/iam-users.json")

	// Verify violation points to the aggregated evidence file
	require.Len(t, storedResult.Violations, 1)
	assert.Equal(t, "evidence/iam-users.json", storedResult.Violations[0].Details["evidence_file"])

	// EvidenceCount reflects total individual resources stored (2 IAM users + 1 S3 bucket = 3)
	assert.Equal(t, 3, manifest.EvidenceCount)
}

func TestStoreRun_WithAttestation(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "test-run-att",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:      "soc2-cc6.1-mfa",
				ControlID:     "CC6.1",
				Status:        evidence.StatusPass,
				ResourceTypes: []string{"aws:iam:user"},
			},
		},
	}
	result.CalculateSummary()

	att := &attestation.Attestation{
		ID:        "att-123",
		RunID:     "test-run-att",
		Framework: "soc2",
		Timestamp: ts,
	}

	manifest, err := StoreRun(context.Background(), backend, result, nil, att)
	require.NoError(t, err)

	basePath := "runs/soc2/2026-02-14"
	assert.NotEmpty(t, manifest.Attestation)
	assert.Equal(t, basePath+"/attestation.json", manifest.Attestation)

	// Verify attestation file exists
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "attestation.json"))
	require.NoError(t, err)
}

func TestStoreRun_NilAttestation(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "test-run-noatt",
		Framework: "soc2",
		Timestamp: ts,
	}
	result.CalculateSummary()

	manifest, err := StoreRun(context.Background(), backend, result, nil, nil)
	require.NoError(t, err)

	// No attestation stored
	assert.Empty(t, manifest.Attestation)

	basePath := "runs/soc2/2026-02-14"
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "attestation.json"))
	assert.True(t, os.IsNotExist(err))
}

func TestStoreRun_EvidenceDeduplication(t *testing.T) {
	// When multiple policies share the same resource type, the aggregated evidence file
	// should appear in each policy's folder (by design - auditor clarity over dedup)
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "test-dedup",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:      "soc2-policy-a",
				ControlID:     "CC1",
				Status:        evidence.StatusPass,
				ResourceTypes: []string{"aws:iam:user"},
			},
			{
				PolicyID:      "soc2-policy-b",
				ControlID:     "CC2",
				Status:        evidence.StatusPass,
				ResourceTypes: []string{"aws:iam:user"},
			},
		},
	}
	result.CalculateSummary()

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", []byte(`{"name":"alice"}`)),
	}

	manifest, err := StoreRun(context.Background(), backend, result, evidenceList, nil)
	require.NoError(t, err)

	basePath := "runs/soc2/2026-02-14"

	// Aggregated evidence should appear in both policy folders
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "policy-a", "evidence", "iam-users.json"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, basePath, "policy-b", "evidence", "iam-users.json"))
	require.NoError(t, err)

	// Evidence count reflects individual resources (1 user x 2 policies = 2)
	assert.Equal(t, 2, manifest.EvidenceCount)
}

func TestLoadManifest(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "load-test-run",
		Framework: "soc2",
		Timestamp: ts,
	}
	result.CalculateSummary()

	_, err = StoreRun(context.Background(), backend, result, []evidence.Evidence{}, nil)
	require.NoError(t, err)

	// Load it using the new path format
	loaded, err := LoadManifest(context.Background(), backend, "runs/soc2/2026-02-14")
	require.NoError(t, err)

	assert.Equal(t, "load-test-run", loaded.RunID)
	assert.Equal(t, "soc2", loaded.Framework)
}

func TestLoadManifest_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	_, err = LoadManifest(context.Background(), backend, "runs/soc2/2099-01-01")
	require.Error(t, err)
}

func TestStoreRun_NoUUIDsInPaths(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "some-uuid-123",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:      "soc2-cc6.1-mfa",
				ControlID:     "CC6.1",
				Status:        evidence.StatusPass,
				ResourceTypes: []string{"aws:iam:user"},
			},
		},
	}
	result.CalculateSummary()

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", []byte(`{"name":"alice"}`)),
	}

	manifest, err := StoreRun(context.Background(), backend, result, evidenceList, nil)
	require.NoError(t, err)

	// Verify no UUIDs in any stored paths
	for _, item := range manifest.Items {
		assert.Contains(t, item.Path, "2026-02-14")
		assert.NotContains(t, item.Path, "some-uuid-123")
	}
}

// Verify StoredPolicyResult embeds correctly
func TestStoredPolicyResult_JSON(t *testing.T) {
	spr := StoredPolicyResult{
		PolicyResult: evidence.PolicyResult{
			PolicyID:  "soc2-cc6.1-mfa",
			ControlID: "CC6.1",
			Name:      "MFA Required",
			Status:    evidence.StatusFail,
			Severity:  evidence.SeverityHigh,
		},
		EvidenceFiles: []string{"evidence/iam-users.json"},
	}

	data, err := json.Marshal(spr)
	require.NoError(t, err)

	// Verify all fields are present in JSON
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"policy_id"`)
	assert.Contains(t, jsonStr, `"name"`)
	assert.Contains(t, jsonStr, `"evidence_files"`)

	// Round-trip
	var parsed StoredPolicyResult
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "MFA Required", parsed.Name)
	assert.Len(t, parsed.EvidenceFiles, 1)
}

// TestStoreRun_HumanReadablePaths verifies the exact path structure.
func TestStoreRun_HumanReadablePaths(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:      "soc2-cc6.1-mfa",
				ControlID:     "CC6.1",
				Status:        evidence.StatusPass,
				ResourceTypes: []string{"aws:iam:user"},
			},
		},
	}
	result.CalculateSummary()

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::552644938807:user/alice", []byte(`{"user":"alice"}`)),
	}

	manifest, err := StoreRun(context.Background(), backend, result, evidenceList, nil)
	require.NoError(t, err)

	// Collect all paths
	var paths []string
	for _, item := range manifest.Items {
		paths = append(paths, item.Path)
	}

	// Verify expected paths — aggregated evidence file
	expectedPaths := []string{
		"runs/soc2/2026-02-14/cc6.1-mfa/evidence/iam-users.json",
		"runs/soc2/2026-02-14/cc6.1-mfa/result.json",
		"runs/soc2/2026-02-14/check_result.json",
		"runs/soc2/2026-02-14/manifest.json",
	}

	for _, expected := range expectedPaths {
		found := false
		for _, actual := range paths {
			if strings.Contains(actual, expected) || actual == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected path %s not found in manifest items: %v", expected, paths)
	}
}

// TestStoreRun_AggregatedEvidenceContent verifies the content of aggregated evidence files.
func TestStoreRun_AggregatedEvidenceContent(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "test-agg",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:      "soc2-cc6.1-mfa",
				ControlID:     "CC6.1",
				Status:        evidence.StatusFail,
				ResourceTypes: []string{"aws:iam:user"},
			},
		},
	}
	result.CalculateSummary()

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", []byte(`{"user_name":"alice","mfa_enabled":true}`)),
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/bob", []byte(`{"user_name":"bob","mfa_enabled":false}`)),
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/charlie", []byte(`{"user_name":"charlie","mfa_enabled":true}`)),
	}

	_, err = StoreRun(context.Background(), backend, result, evidenceList, nil)
	require.NoError(t, err)

	// Read the aggregated evidence file
	basePath := "runs/soc2/2026-02-14"
	evData, err := os.ReadFile(filepath.Join(tmpDir, basePath, "cc6.1-mfa", "evidence", "iam-users.json"))
	require.NoError(t, err)

	var entries []aggregatedEvidenceEntry
	err = json.Unmarshal(evData, &entries)
	require.NoError(t, err)

	// Should contain all 3 users in one file
	assert.Len(t, entries, 3)

	// Verify each entry has the right structure
	resourceIDs := make([]string, len(entries))
	for i, e := range entries {
		resourceIDs[i] = e.ResourceID
		assert.NotEmpty(t, e.Data, "Evidence data should not be empty")
		assert.False(t, e.CollectedAt.IsZero(), "CollectedAt should be set")
	}

	assert.Contains(t, resourceIDs, "arn:aws:iam::123:user/alice")
	assert.Contains(t, resourceIDs, "arn:aws:iam::123:user/bob")
	assert.Contains(t, resourceIDs, "arn:aws:iam::123:user/charlie")
}
