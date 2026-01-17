package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
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

func TestLocalBackend_Store(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	ev := evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/alice", []byte(`{"user_name":"alice","mfa_enabled":true}`))

	item, err := backend.Store(context.Background(), &ev)
	require.NoError(t, err)

	assert.NotEmpty(t, item.Path)
	assert.NotEmpty(t, item.Hash)
	assert.Greater(t, item.Size, int64(0))
	assert.Equal(t, "application/json", item.ContentType)
	assert.Equal(t, "aws:iam:user", item.Metadata["resource_type"])
	assert.Equal(t, "aws", item.Metadata["collector"])

	// Verify file exists
	fullPath := filepath.Join(tmpDir, item.Path)
	_, err = os.Stat(fullPath)
	require.NoError(t, err)
}

func TestLocalBackend_StoreCheckResult(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	result := &evidence.CheckResult{
		RunID:     "test-run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:  "soc2-cc6.1-mfa",
				ControlID: "CC6.1",
				Status:    evidence.StatusPass,
			},
		},
	}
	result.CalculateSummary()

	item, err := backend.StoreCheckResult(context.Background(), result)
	require.NoError(t, err)

	assert.Contains(t, item.Path, "test-run-123")
	assert.Contains(t, item.Path, "check_result.json")
	assert.NotEmpty(t, item.Hash)
	assert.Equal(t, "soc2", item.Metadata["framework"])
}

func TestLocalBackend_Get(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	err := backend.Init(context.Background())
	require.NoError(t, err)

	// Store evidence first
	ev := evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/bob", []byte(`{"user_name":"bob"}`))
	item, err := backend.Store(context.Background(), &ev)
	require.NoError(t, err)

	// Retrieve it
	data, err := backend.Get(context.Background(), item.Path)
	require.NoError(t, err)

	var retrieved evidence.Evidence
	err = json.Unmarshal(data, &retrieved)
	require.NoError(t, err)
	assert.Equal(t, "aws:iam:user", retrieved.ResourceType)
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

	// Store multiple evidence items
	for _, username := range []string{"alice", "bob", "charlie"} {
		ev := evidence.New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/"+username, []byte(`{"user_name":"`+username+`"}`))
		_, err := backend.Store(context.Background(), &ev)
		require.NoError(t, err)
	}

	// List all
	items, err := backend.List(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, items, 3)

	// List with prefix
	items, err = backend.List(context.Background(), &ListFilter{Prefix: "evidence"})
	require.NoError(t, err)
	assert.Len(t, items, 3)

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

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with/slash", "with_slash"},
		{"with:colon", "with_colon"},
		{"arn:aws:iam::123:user/alice", "arn_aws_iam__123_user_alice"},
		{"file<>name", "file__name"},
		{"file*name?", "file_name_"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStoredItem_JSON(t *testing.T) {
	item := StoredItem{
		Path:        "evidence/aws/iam/user/alice.json",
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
		Items: []StoredItem{
			{Path: "evidence/test.json", Hash: "abc"},
		},
	}

	data, err := json.Marshal(manifest)
	require.NoError(t, err)

	var parsed Manifest
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, manifest.RunID, parsed.RunID)
	assert.Len(t, parsed.Items, 1)
}
