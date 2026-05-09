package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	path := "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence/iam-users.json"

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
	path := "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence/iam-users.json"

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
		"soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence/iam-users.json",
		"soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/result.json",
		"soc2/cc6.2-encryption/20260214T182049Z_a3f8b2c1/evidence/s3-buckets.json",
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
	items, err = backend.List(context.Background(), &ListFilter{Prefix: "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence"})
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
		Path:        "soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence/iam-users.json",
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

// Verify StoredPolicyResult embeds correctly and includes new fields
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
		CLIVersion:    "1.2.3",
		CLISHA:        "abc123def456",
		RepoSHA:       "def456abc123",
	}

	data, err := json.Marshal(spr)
	require.NoError(t, err)

	// Verify all fields are present in JSON
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"policy_id"`)
	assert.Contains(t, jsonStr, `"name"`)
	assert.Contains(t, jsonStr, `"evidence_files"`)
	assert.Contains(t, jsonStr, `"cli_version"`)
	assert.Contains(t, jsonStr, `"cli_sha"`)
	assert.Contains(t, jsonStr, `"repo_sha"`)

	// Round-trip
	var parsed StoredPolicyResult
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "MFA Required", parsed.Name)
	assert.Len(t, parsed.EvidenceFiles, 1)
	assert.Equal(t, "1.2.3", parsed.CLIVersion)
	assert.Equal(t, "abc123def456", parsed.CLISHA)
	assert.Equal(t, "def456abc123", parsed.RepoSHA)
}

func TestStoreRun_PolicyCentricLayout(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	runID := "test-run-123-xxxx"
	result := &evidence.CheckResult{
		RunID:     runID,
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
				PolicyID:           "soc2-cc6.2-encryption",
				ControlID:          "CC6.2",
				Name:               "Encryption Required",
				Status:             evidence.StatusPass,
				Severity:           evidence.SeverityHigh,
				Message:            "All resources compliant",
				ResourceTypes:      []string{"aws:s3:bucket"},
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

	err = StoreRun(context.Background(), backend, result, evidenceList, nil, "1.0.0", "abc123", "def456")
	require.NoError(t, err)

	// Compute expected paths
	rp1 := NewRunPath("soc2", "soc2-cc6.1-mfa", runID, ts)
	rp2 := NewRunPath("soc2", "soc2-cc6.2-encryption", runID, ts)

	// cc6.1-mfa: evidence + result
	_, err = os.Stat(filepath.Join(tmpDir, rp1.EvidencePath("iam-users.json")))
	require.NoError(t, err, "iam-users.json should exist")

	_, err = os.Stat(filepath.Join(tmpDir, rp1.ResultPath()))
	require.NoError(t, err, "cc6.1-mfa result.json should exist")

	// cc6.2-encryption: evidence + result
	_, err = os.Stat(filepath.Join(tmpDir, rp2.EvidencePath("s3-buckets.json")))
	require.NoError(t, err, "s3-buckets.json should exist")

	_, err = os.Stat(filepath.Join(tmpDir, rp2.ResultPath()))
	require.NoError(t, err, "cc6.2-encryption result.json should exist")

	// No manifest.json or check_result.json at any shared run level
	items, err := backend.List(context.Background(), nil)
	require.NoError(t, err)
	for _, item := range items {
		assert.NotContains(t, item.Path, "manifest.json")
		assert.NotContains(t, item.Path, "check_result.json")
	}

	// Verify per-policy result.json content
	resultData, err := os.ReadFile(filepath.Join(tmpDir, rp1.ResultPath()))
	require.NoError(t, err)

	var storedResult StoredPolicyResult
	err = json.Unmarshal(resultData, &storedResult)
	require.NoError(t, err)

	assert.Equal(t, "soc2-cc6.1-mfa", storedResult.PolicyID)
	assert.Equal(t, evidence.StatusFail, storedResult.Status)
	assert.Equal(t, "MFA Required", storedResult.Name)
	assert.Len(t, storedResult.EvidenceFiles, 1)
	assert.Contains(t, storedResult.EvidenceFiles, "evidence/iam-users.json")

	// CLIVersion and SHAs should be stored
	assert.Equal(t, "1.0.0", storedResult.CLIVersion)
	assert.Equal(t, "abc123", storedResult.CLISHA)
	assert.Equal(t, "def456", storedResult.RepoSHA)

	// Violation points to the aggregated evidence file
	require.Len(t, storedResult.Violations, 1)
	assert.Equal(t, "evidence/iam-users.json", storedResult.Violations[0].Details["evidence_file"])
}

func TestStoreRun_EvidenceEnvelopeVerifies(t *testing.T) {
	// Evidence files must be valid signed EvidenceEnvelopes that pass verification.
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	runID := "verify-run-xx"
	result := &evidence.CheckResult{
		RunID:     runID,
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
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", []byte(`{"mfa":true}`)),
	}

	err = StoreRun(context.Background(), backend, result, evidenceList, nil, "", "", "")
	require.NoError(t, err)

	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", runID, ts)
	evData, err := os.ReadFile(filepath.Join(tmpDir, rp.EvidencePath("iam-users.json")))
	require.NoError(t, err)

	// Must unmarshal as EvidenceEnvelope
	var envelope attestation.EvidenceEnvelope
	err = json.Unmarshal(evData, &envelope)
	require.NoError(t, err)

	assert.Equal(t, attestation.AlgorithmEd25519, envelope.Signature.Algorithm)
	assert.NotEmpty(t, envelope.PublicKey)
	assert.NotEmpty(t, envelope.Signature.Value)
	assert.Equal(t, ts, envelope.Signed.Timestamp)

	// Signature must verify
	verifier := attestation.NewEd25519Verifier()
	err = verifier.Verify(&envelope)
	require.NoError(t, err, "Evidence envelope signature should verify")

	// The signed evidence should contain our entry
	var entries []aggregatedEvidenceEntry
	err = json.Unmarshal(envelope.Signed.Evidence, &entries)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "arn:aws:iam::123:user/alice", entries[0].ResourceID)
}

func TestStoreRun_EvidenceDuplicatedPerPolicy(t *testing.T) {
	// When multiple policies share the same resource type, evidence appears in each
	// policy folder independently (auditor self-containment over deduplication).
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	runID := "dedup-run-xxxxx"
	result := &evidence.CheckResult{
		RunID:     runID,
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

	err = StoreRun(context.Background(), backend, result, evidenceList, nil, "", "", "")
	require.NoError(t, err)

	rp1 := NewRunPath("soc2", "soc2-policy-a", runID, ts)
	rp2 := NewRunPath("soc2", "soc2-policy-b", runID, ts)

	// Evidence should appear in both policy folders
	_, err = os.Stat(filepath.Join(tmpDir, rp1.EvidencePath("iam-users.json")))
	require.NoError(t, err, "policy-a should have iam-users.json")

	_, err = os.Stat(filepath.Join(tmpDir, rp2.EvidencePath("iam-users.json")))
	require.NoError(t, err, "policy-b should have iam-users.json")
}

func TestStoreRun_NoUUIDsInPaths(t *testing.T) {
	// Full run UUID must not appear in stored paths — only the first 8 chars are used.
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	runID := "some-uuid-123"
	result := &evidence.CheckResult{
		RunID:     runID,
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

	err = StoreRun(context.Background(), backend, result, evidenceList, nil, "", "", "")
	require.NoError(t, err)

	items, err := backend.List(context.Background(), nil)
	require.NoError(t, err)

	// Paths contain the first 8 chars of the run ID but not the full run ID
	runIDShort := runID[:8]
	for _, item := range items {
		assert.Contains(t, item.Path, runIDShort,
			"Path should contain short run ID prefix")
		assert.NotContains(t, item.Path, runID,
			"Path should not contain the full run ID")
	}
}

func TestStoreRun_HumanReadablePaths(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	runID := "a3f8b2c1-dead-beef-1234-567890abcdef"
	result := &evidence.CheckResult{
		RunID:     runID,
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

	err = StoreRun(context.Background(), backend, result, evidenceList, nil, "", "", "")
	require.NoError(t, err)

	items, err := backend.List(context.Background(), nil)
	require.NoError(t, err)

	paths := make([]string, 0, len(items))
	for _, item := range items {
		paths = append(paths, item.Path)
	}

	// ISO 8601 basic timestamp + first 8 chars of run ID
	expectedPaths := []string{
		"soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/evidence/iam-users.json",
		"soc2/cc6.1-mfa/20260214T182049Z_a3f8b2c1/result.json",
	}

	for _, expected := range expectedPaths {
		found := false
		for _, actual := range paths {
			if actual == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected path %s not found in stored items: %v", expected, paths)
	}
}

func TestStoreRun_AggregatedEvidenceContent(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	runID := "agg-test-xxxxx"
	result := &evidence.CheckResult{
		RunID:     runID,
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

	err = StoreRun(context.Background(), backend, result, evidenceList, nil, "", "", "")
	require.NoError(t, err)

	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", runID, ts)
	evData, err := os.ReadFile(filepath.Join(tmpDir, rp.EvidencePath("iam-users.json")))
	require.NoError(t, err)

	// File is an EvidenceEnvelope — unmarshal and extract the signed evidence
	var envelope attestation.EvidenceEnvelope
	err = json.Unmarshal(evData, &envelope)
	require.NoError(t, err)

	var entries []aggregatedEvidenceEntry
	err = json.Unmarshal(envelope.Signed.Evidence, &entries)
	require.NoError(t, err)

	// Should contain all 3 users in one file
	assert.Len(t, entries, 3)

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

func TestStoreRun_EmptyEvidenceList(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "empty-run-xxxx",
		Framework: "soc2",
		Timestamp: ts,
	}
	result.CalculateSummary()

	// No evidence, no policy results — should succeed silently
	err = StoreRun(context.Background(), backend, result, nil, nil, "", "", "")
	require.NoError(t, err)
}

func TestStoreRun_MirrorsManualSidecarsIntoPolicyFolder(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	runID := "manual-run-xxxx"
	const evidenceID = "cc6_1_security_training"
	resourceType := "manual:" + evidenceID

	result := &evidence.CheckResult{
		RunID:     runID,
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{{
			PolicyID:      "soc2-cc6.1-security-training",
			ControlID:     "CC6.1",
			Name:          "Security Training",
			Status:        evidence.StatusPass,
			Severity:      evidence.SeverityMedium,
			ResourceTypes: []string{resourceType},
		}},
	}
	result.CalculateSummary()

	evidenceList := []evidence.Evidence{
		evidence.New("manual", resourceType, evidenceID+"/2026-Q1", []byte(`{"status":"uploaded"}`)),
	}

	pdfBytes := []byte("%PDF-1.4 fake")
	sidecars := []ManualSidecar{{
		EvidenceID:   evidenceID,
		Period:       "2026-Q1",
		ResourceType: resourceType,
		PDF:          pdfBytes,
		FileHash:     "sha256-of-fake-pdf",
	}}

	err = StoreRun(context.Background(), backend, result, evidenceList, sidecars, "", "", "")
	require.NoError(t, err)

	rp := NewRunPath("soc2", "soc2-cc6.1-security-training", runID, ts)

	gotPDF, err := backend.Get(context.Background(), rp.ManualAttachmentPath(evidenceID, "evidence.pdf"))
	require.NoError(t, err, "manual evidence.pdf should be mirrored into policy folder")
	assert.Equal(t, pdfBytes, gotPDF)
}

func TestStoreRun_SkipsSidecarsWhenPolicyDoesNotReferenceThem(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ts := time.Date(2026, 2, 14, 18, 20, 49, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "skip-run-xxxx",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{{
			PolicyID:      "soc2-cc6.1-mfa",
			ControlID:     "CC6.1",
			Name:          "MFA",
			Status:        evidence.StatusPass,
			ResourceTypes: []string{"aws:iam:user"},
		}},
	}
	result.CalculateSummary()

	// Sidecar exists but no policy references manual:<id> — must not be written.
	sidecars := []ManualSidecar{{
		EvidenceID:   "cc6_1_security_training",
		ResourceType: "manual:cc6_1_security_training",
		PDF:          []byte("%PDF-1.4 unused"),
		FileHash:     "abc",
	}}

	err = StoreRun(context.Background(), backend, result, nil, sidecars, "", "", "")
	require.NoError(t, err)

	rp := NewRunPath("soc2", "soc2-cc6.1-mfa", "skip-run-xxxx", ts)
	_, err = backend.Get(context.Background(), rp.ManualAttachmentPath("cc6_1_security_training", "evidence.pdf"))
	require.Error(t, err, "sidecar must not be written for unrelated policies")
}
