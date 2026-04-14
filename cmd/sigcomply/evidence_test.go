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

func TestEvidenceSchema_ValidJSONSchema(t *testing.T) {
	schema := manual.SubmittedEvidenceSchema()

	// Should be valid JSON (marshal + unmarshal round-trip)
	data, err := json.Marshal(schema)
	require.NoError(t, err)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &decoded))

	// Verify key JSON Schema fields
	assert.Equal(t, "https://json-schema.org/draft/2020-12/schema", decoded["$schema"])
	assert.Equal(t, "SubmittedEvidence", decoded["title"])
	assert.Equal(t, "object", decoded["type"])

	// Verify required fields exist
	required, ok := decoded["required"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, required, "schema_version")
	assert.Contains(t, required, "evidence_id")
	assert.Contains(t, required, "type")

	// Verify properties exist
	props, ok := decoded["properties"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, props, "schema_version")
	assert.Contains(t, props, "evidence_id")
	assert.Contains(t, props, "items")
	assert.Contains(t, props, "attachments")
	assert.Contains(t, props, "declaration_text")
	assert.Contains(t, props, "accepted")

	// Verify conditional required (allOf)
	allOf, ok := decoded["allOf"].([]interface{})
	require.True(t, ok)
	assert.Len(t, allOf, 3) // document_upload, checklist, declaration
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
