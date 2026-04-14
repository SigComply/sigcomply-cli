package manual

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

func newTestBackend(t *testing.T) storage.Backend {
	t.Helper()
	backend := storage.NewLocalBackend(&storage.LocalConfig{Path: t.TempDir()})
	require.NoError(t, backend.Init(context.Background()))
	return backend
}

func TestLoadState_NotFound(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	state, err := LoadState(ctx, backend, "execution-state.json")
	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, "1.0", state.SchemaVersion)
	assert.Empty(t, state.Manual)
}

func TestState_SaveAndLoad(t *testing.T) {
	backend := newTestBackend(t)
	ctx := context.Background()

	state := NewExecutionState("soc2")
	state.RecordAttestation("quarterly_access_review", "2026-Q1", "run-123", "attested", map[string]string{
		"report.pdf": "abc123",
	})

	require.NoError(t, state.Save(ctx, backend, "execution-state.json"))

	loaded, err := LoadState(ctx, backend, "execution-state.json")
	require.NoError(t, err)

	assert.Equal(t, "soc2", loaded.Framework)
	assert.True(t, loaded.IsAttested("quarterly_access_review", "2026-Q1"))
	assert.False(t, loaded.IsAttested("quarterly_access_review", "2026-Q2"))
	assert.False(t, loaded.IsAttested("nonexistent", "2026-Q1"))

	entry := loaded.Manual["quarterly_access_review"]["2026-Q1"]
	assert.Equal(t, "attested", entry.Status)
	assert.Equal(t, "run-123", entry.RunID)
	assert.Equal(t, "abc123", entry.FileHashes["report.pdf"])
	assert.NotNil(t, entry.AttestedAt)
}

func TestState_IsAttested_UploadedNotAttested(t *testing.T) {
	state := NewExecutionState("soc2")
	state.Manual["test_evidence"] = map[string]Entry{
		"2026-Q1": {Status: "uploaded"},
	}

	assert.False(t, state.IsAttested("test_evidence", "2026-Q1"))
}

func TestState_RecordAttestation_OverwritesPrevious(t *testing.T) {
	state := NewExecutionState("soc2")
	state.RecordAttestation("test", "2026-Q1", "run-1", "uploaded", map[string]string{"a.pdf": "hash1"})
	assert.False(t, state.IsAttested("test", "2026-Q1"))

	state.RecordAttestation("test", "2026-Q1", "run-2", "attested", map[string]string{"a.pdf": "hash2"})
	assert.True(t, state.IsAttested("test", "2026-Q1"))
	assert.Equal(t, "run-2", state.Manual["test"]["2026-Q1"].RunID)
}
