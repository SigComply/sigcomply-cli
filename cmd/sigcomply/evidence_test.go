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
	manualDir := filepath.Join(tmpDir, "manual-evidence")

	cfg := config.New()
	cfg.Framework = frameworkSOC2
	cfg.ManualEvidence.Enabled = true
	cfg.ManualEvidence.Default = &config.StorageConfig{
		Backend: "local",
		Path:    manualDir,
	}

	storageCfg, err := buildManualStorageConfig(cfg)
	require.NoError(t, err)
	backend, err := storage.NewBackend(storageCfg)
	require.NoError(t, err)
	require.NoError(t, backend.Init(context.Background()))

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

func TestBuildManualStorageConfig_DefaultLocal(t *testing.T) {
	cfg := config.New()
	cfg.Framework = frameworkSOC2
	cfg.ManualEvidence.Default = &config.StorageConfig{
		Backend: "local",
		Path:    "/tmp/manual-evidence",
	}

	storageCfg, err := buildManualStorageConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "local", storageCfg.Backend)
	assert.Equal(t, "/tmp/manual-evidence", storageCfg.Local.Path)
}

func TestBuildManualStorageConfig_PerFrameworkS3(t *testing.T) {
	cfg := config.New()
	cfg.Framework = frameworkSOC2
	cfg.ManualEvidence.Frameworks = map[string]*config.StorageConfig{
		frameworkSOC2: {
			Backend: "s3",
			Bucket:  "soc2-evidence",
			Region:  "us-east-1",
			Prefix:  "manual/",
		},
	}

	storageCfg, err := buildManualStorageConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "s3", storageCfg.Backend)
	assert.Equal(t, "soc2-evidence", storageCfg.S3.Bucket)
	assert.Equal(t, "manual/", storageCfg.S3.Prefix)
}

func TestBuildManualStorageConfig_NoSourceErrors(t *testing.T) {
	cfg := config.New()
	cfg.Framework = frameworkSOC2
	// Neither Default nor Frameworks[soc2] set.

	_, err := buildManualStorageConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "soc2")
}
