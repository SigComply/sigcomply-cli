package manual

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	manualPkg "github.com/sigcomply/sigcomply-cli/internal/core/manual"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

func setupTest(t *testing.T) (context.Context, storage.Backend, *manualPkg.Catalog, *manualPkg.ExecutionState) {
	t.Helper()
	ctx := context.Background()
	backend := storage.NewLocalBackend(&storage.LocalConfig{Path: t.TempDir()})
	require.NoError(t, backend.Init(ctx))

	catalog, err := manualPkg.LoadCatalog("soc2")
	require.NoError(t, err)

	state := manualPkg.NewExecutionState("soc2")
	return ctx, backend, catalog, state
}

func storePDF(ctx context.Context, t *testing.T, backend storage.Backend, evidenceID, period string, body []byte) string {
	t.Helper()
	path := filepath.Join("soc2", evidenceID, period, manualPkg.EvidencePDFFilename)
	_, err := backend.StoreRaw(ctx, path, body, nil)
	require.NoError(t, err)
	return path
}

func TestReader_MissingEvidence(t *testing.T) {
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	reader := NewReader(backend, catalog, "soc2")
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)

	// Every catalog entry produces an evidence record (status = not_uploaded
	// when no PDF is present).
	assert.Len(t, result.Evidence, len(catalog.Entries))
	assert.Empty(t, result.Sidecars, "no PDFs uploaded → no sidecars")

	for _, ev := range result.Evidence {
		assert.Equal(t, "manual", ev.Collector)
		var data map[string]interface{}
		require.NoError(t, json.Unmarshal(ev.Data, &data))
		assert.Equal(t, "not_uploaded", data["status"])
		assert.NotContains(t, data, "file_hash")
		assert.NotContains(t, data, "file_path")
	}
}

func TestReader_PDFPresent(t *testing.T) {
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	pdfBody := []byte("%PDF-1.4 test contents")
	expectedHashBytes := sha256.Sum256(pdfBody)
	expectedHash := hex.EncodeToString(expectedHashBytes[:])
	expectedPath := storePDF(ctx, t, backend, "quarterly_access_review", "2026-Q1", pdfBody)

	reader := NewReader(backend, catalog, "soc2")
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)

	var found bool
	for _, ev := range result.Evidence {
		if ev.ResourceType != "manual:quarterly_access_review" {
			continue
		}
		found = true
		var data map[string]interface{}
		require.NoError(t, json.Unmarshal(ev.Data, &data))
		assert.Equal(t, "uploaded", data["status"])
		assert.Equal(t, expectedHash, data["file_hash"])
		assert.Equal(t, expectedPath, data["file_path"])
	}
	require.True(t, found, "expected manual:quarterly_access_review in evidence list")

	// Sidecar carries the raw PDF bytes + hash for the storage layer to mirror.
	var sidecar *storage.ManualSidecar
	for i := range result.Sidecars {
		if result.Sidecars[i].EvidenceID == "quarterly_access_review" {
			sidecar = &result.Sidecars[i]
			break
		}
	}
	require.NotNil(t, sidecar, "expected sidecar for quarterly_access_review")
	assert.Equal(t, "manual:quarterly_access_review", sidecar.ResourceType)
	assert.Equal(t, "2026-Q1", sidecar.Period)
	assert.Equal(t, pdfBody, sidecar.PDF)
	assert.Equal(t, expectedHash, sidecar.FileHash)
}

func TestReader_AlreadyAttested(t *testing.T) {
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	// Mark one entry as attested for the current period — reader should skip it.
	state.RecordAttestation("quarterly_access_review", "2026-Q1", "run-1", "attested", map[string]string{
		manualPkg.EvidencePDFFilename: "abc",
	})

	reader := NewReader(backend, catalog, "soc2")
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)

	assert.Len(t, result.Evidence, len(catalog.Entries)-1)
	for _, ev := range result.Evidence {
		assert.NotEqual(t, "manual:quarterly_access_review", ev.ResourceType)
	}
}

func TestReader_OpaquePDF(t *testing.T) {
	// The CLI does not parse the PDF in v1 — any byte payload at the right path
	// is treated as "uploaded". This guards against accidentally adding format
	// validation here in the future.
	ctx, backend, catalog, state := setupTest(t)
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	storePDF(ctx, t, backend, "quarterly_access_review", "2026-Q1", []byte("not really a PDF"))

	reader := NewReader(backend, catalog, "soc2")
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)
	assert.Empty(t, result.Errors)

	var found bool
	for _, ev := range result.Evidence {
		if ev.ResourceType == "manual:quarterly_access_review" {
			found = true
			var data map[string]interface{}
			require.NoError(t, json.Unmarshal(ev.Data, &data))
			assert.Equal(t, "uploaded", data["status"])
		}
	}
	assert.True(t, found)
}
