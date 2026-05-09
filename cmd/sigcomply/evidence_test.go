package sigcomply

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigcomply/sigcomply-cli/internal/core/config"
	"github.com/sigcomply/sigcomply-cli/internal/core/manual"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

func TestEvidenceInit_CreatesFolders(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.New()
	cfg.Framework = frameworkSOC2
	cfg.Storage.Backend = "local"
	cfg.Storage.Path = tmpDir
	cfg.ManualEvidence.Enabled = true

	storageCfg := buildManualStorageConfig(cfg)
	backend, err := storage.NewBackend(storageCfg)
	require.NoError(t, err)
	require.NoError(t, backend.Init(context.Background()))

	// Verify the manual evidence prefix directory exists
	manualDir := filepath.Join(tmpDir, "manual-evidence")
	_, err = os.Stat(manualDir)
	require.NoError(t, err)
}

func TestEvidenceInit_CreatesExecutionState(t *testing.T) {
	tmpDir := t.TempDir()
	manualDir := filepath.Join(tmpDir, "manual-evidence")

	backend := storage.NewLocalBackend(&storage.LocalConfig{Path: manualDir})
	require.NoError(t, backend.Init(context.Background()))

	state := manual.NewExecutionState(frameworkSOC2)
	statePath := filepath.Join(frameworkSOC2, "execution-state.json")
	require.NoError(t, state.Save(context.Background(), backend, statePath))

	// Load it back
	loaded, err := manual.LoadState(context.Background(), backend, statePath)
	require.NoError(t, err)
	assert.Equal(t, frameworkSOC2, loaded.Framework)
}

func TestEvidenceCatalog_JSONOutput(t *testing.T) {
	catalog, err := manual.LoadCatalog(frameworkSOC2)
	require.NoError(t, err)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(catalog))

	var decoded manual.Catalog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))

	assert.Equal(t, frameworkSOC2, decoded.Framework)
	assert.GreaterOrEqual(t, len(decoded.Entries), 4)
}

func TestBuildManualStorageConfig_Local(t *testing.T) {
	cfg := config.New()
	cfg.Storage.Backend = "local"
	cfg.Storage.Path = "/tmp/evidence"
	cfg.ManualEvidence.Prefix = "manual-evidence/"

	storageCfg := buildManualStorageConfig(cfg)
	assert.Equal(t, "local", storageCfg.Backend)
	assert.Equal(t, "/tmp/evidence/manual-evidence", storageCfg.Local.Path)
}

func TestBuildManualStorageConfig_S3(t *testing.T) {
	cfg := config.New()
	cfg.Storage.Backend = "s3"
	cfg.Storage.Bucket = "my-bucket"
	cfg.Storage.Region = "us-east-1"
	cfg.Storage.Prefix = "compliance/"
	cfg.ManualEvidence.Prefix = "manual-evidence/"

	storageCfg := buildManualStorageConfig(cfg)
	assert.Equal(t, "s3", storageCfg.Backend)
	assert.Equal(t, "my-bucket", storageCfg.S3.Bucket)
	assert.Equal(t, "compliance/manual-evidence/", storageCfg.S3.Prefix)
}
