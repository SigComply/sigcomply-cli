// Package manual reads user-supplied evidence.pdf files from storage and
// produces evidence items for OPA evaluation.
//
// The reader does not parse PDF contents in v1 — it only checks presence and
// hashes the bytes. The OPA evidence record it emits is small and uniform:
//
//	{evidence_id, status, period, temporal_status, file_hash, file_path}
//
// Manual policies (those with evidence_type: "manual" metadata) consume this
// record. Future text-extraction policies will layer on top of the same record
// without changing the contract.
package manual

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	manualPkg "github.com/sigcomply/sigcomply-cli/internal/core/manual"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

// Reader reads manual evidence PDFs from storage and produces evidence items.
type Reader struct {
	backend   storage.Backend
	catalog   *manualPkg.Catalog
	framework string
}

// ReadResult contains the evidence items and any errors encountered.
type ReadResult struct {
	Evidence []evidence.Evidence
	Errors   []ReadError
	Status   []EntryStatus
	// Sidecars carries the raw PDF bytes for each manual entry that had a
	// user-uploaded file, so the storage layer can mirror them into the policy
	// result bucket alongside the signed envelope.
	Sidecars []storage.ManualSidecar
}

// ReadError records an error for a specific evidence entry.
type ReadError struct {
	EvidenceID string
	Err        string
}

// EntryStatus summarizes the status of a single catalog entry.
type EntryStatus struct {
	EvidenceID     string
	Period         string
	TemporalStatus string
	HasEvidence    bool
	Attested       bool
	// ExpectedURI is the fully-qualified URI where the user is expected to
	// upload evidence.pdf (e.g. s3://bucket/key, gs://bucket/key,
	// https://account.blob.core.windows.net/container/key, file:///abs/path).
	// Surfaced in CLI output and OPA violation messages.
	ExpectedURI string
}

// NewReader creates a new manual evidence reader.
func NewReader(backend storage.Backend, catalog *manualPkg.Catalog, framework string) *Reader {
	return &Reader{
		backend:   backend,
		catalog:   catalog,
		framework: framework,
	}
}

// Read processes all catalog entries and returns evidence items for OPA evaluation.
func (r *Reader) Read(ctx context.Context, state *manualPkg.ExecutionState, now time.Time) (*ReadResult, error) {
	result := &ReadResult{}

	for i := range r.catalog.Entries {
		ev, entryStatus, sidecar, readErr := r.readEntry(ctx, &r.catalog.Entries[i], state, now)
		result.Status = append(result.Status, entryStatus)
		if readErr != nil {
			result.Errors = append(result.Errors, ReadError{
				EvidenceID: r.catalog.Entries[i].ID,
				Err:        readErr.Error(),
			})
			continue
		}
		result.Evidence = append(result.Evidence, ev)
		if sidecar != nil {
			result.Sidecars = append(result.Sidecars, *sidecar)
		}
	}

	return result, nil
}

func (r *Reader) readEntry(ctx context.Context, entry *manualPkg.CatalogEntry, state *manualPkg.ExecutionState, now time.Time) (evidence.Evidence, EntryStatus, *storage.ManualSidecar, error) {
	period, err := manualPkg.CurrentPeriod(entry.Frequency, now, entry.GracePeriod)
	if err != nil {
		return evidence.Evidence{}, EntryStatus{EvidenceID: entry.ID}, nil, fmt.Errorf("period computation: %w", err)
	}

	pdfPath, err := manualPkg.ResolvePath(entry, r.framework, &period)
	if err != nil {
		return evidence.Evidence{}, EntryStatus{EvidenceID: entry.ID}, nil, fmt.Errorf("resolve path: %w", err)
	}
	expectedURI := r.backend.URIFor(pdfPath)

	status := EntryStatus{
		EvidenceID:  entry.ID,
		Period:      period.Key,
		Attested:    state.IsAttested(entry.ID, period.Key),
		ExpectedURI: expectedURI,
	}

	// Skip entries that are already attested for this period (idempotent reruns).
	if status.Attested {
		status.TemporalStatus = string(manualPkg.TemporalStatusWithinWindow)
		status.HasEvidence = true
		return evidence.Evidence{}, status, nil, fmt.Errorf("already attested")
	}

	pdfBytes, getErr := r.backend.Get(ctx, pdfPath)

	if getErr != nil {
		var notFound *storage.NotFoundError
		if !errors.As(getErr, &notFound) {
			return evidence.Evidence{}, status, nil, fmt.Errorf("storage error: %w", getErr)
		}

		temporalStatus := manualPkg.ComputeTemporalStatus(&period, now, false)
		status.TemporalStatus = string(temporalStatus)
		status.HasEvidence = false

		opaData := map[string]interface{}{
			"evidence_id":     entry.ID,
			"status":          "not_uploaded",
			"period":          period.Key,
			"temporal_status": string(temporalStatus),
			"expected_path":   pdfPath,
			"expected_uri":    expectedURI,
		}
		jsonData, marshalErr := json.Marshal(opaData)
		if marshalErr != nil {
			return evidence.Evidence{}, status, nil, fmt.Errorf("marshal OPA data: %w", marshalErr)
		}

		ev := evidence.New("manual", "manual:"+entry.ID, entry.ID+"/"+period.Key, jsonData)
		return ev, status, nil, nil
	}

	// PDF is present. Hash the bytes and emit an OPA record referencing them.
	hash := sha256.Sum256(pdfBytes)
	fileHash := hex.EncodeToString(hash[:])

	status.HasEvidence = true
	temporalStatus := manualPkg.ComputeTemporalStatus(&period, now, true)
	status.TemporalStatus = string(temporalStatus)

	opaData := map[string]interface{}{
		"evidence_id":     entry.ID,
		"status":          "uploaded",
		"period":          period.Key,
		"temporal_status": string(temporalStatus),
		"file_hash":       fileHash,
		"file_path":       pdfPath,
		"expected_uri":    expectedURI,
	}
	jsonData, marshalErr := json.Marshal(opaData)
	if marshalErr != nil {
		return evidence.Evidence{}, status, nil, fmt.Errorf("marshal OPA data: %w", marshalErr)
	}
	ev := evidence.New("manual", "manual:"+entry.ID, entry.ID+"/"+period.Key, jsonData)

	sidecar := &storage.ManualSidecar{
		EvidenceID:   entry.ID,
		Period:       period.Key,
		ResourceType: "manual:" + entry.ID,
		PDF:          pdfBytes,
		FileHash:     fileHash,
	}
	return ev, status, sidecar, nil
}
