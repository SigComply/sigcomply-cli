// Package manual reads manually uploaded evidence from storage and produces evidence items for OPA evaluation.
package manual

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	manualPkg "github.com/sigcomply/sigcomply-cli/internal/core/manual"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

// Reader reads manual evidence from storage and produces evidence items.
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
	// Sidecars carries the raw evidence.json + supporting files for each manual
	// entry that had user-uploaded data, so the storage layer can mirror them
	// into the policy result bucket alongside the OPA-derived envelope.
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

	status := EntryStatus{
		EvidenceID: entry.ID,
		Period:     period.Key,
		Attested:   state.IsAttested(entry.ID, period.Key),
	}

	// Skip if already attested
	if status.Attested {
		status.TemporalStatus = string(manualPkg.TemporalStatusWithinWindow)
		status.HasEvidence = true
		return evidence.Evidence{}, status, nil, fmt.Errorf("already attested")
	}

	// Try to read submitted evidence from storage
	evidencePath := filepath.Join(r.framework, entry.ID, period.Key, "evidence.json")
	data, getErr := r.backend.Get(ctx, evidencePath)

	if getErr != nil {
		// Not found — build "not_uploaded" evidence for OPA
		var notFound *storage.NotFoundError
		if !errors.As(getErr, &notFound) {
			return evidence.Evidence{}, status, nil, fmt.Errorf("storage error: %w", getErr)
		}

		temporalStatus := manualPkg.ComputeTemporalStatus(&period, now, false)
		status.TemporalStatus = string(temporalStatus)
		status.HasEvidence = false

		opaData := map[string]interface{}{
			"evidence_id":     entry.ID,
			"type":            string(entry.Type),
			"status":          "not_uploaded",
			"period":          period.Key,
			"temporal_status": string(temporalStatus),
		}
		jsonData, marshalErr := json.Marshal(opaData)
		if marshalErr != nil {
			return evidence.Evidence{}, status, nil, fmt.Errorf("marshal OPA data: %w", marshalErr)
		}

		ev := evidence.New("manual", "manual:"+entry.ID, entry.ID+"/"+period.Key, jsonData)
		return ev, status, nil, nil
	}

	// Validate against JSON Schema first, so structurally broken submissions produce
	// a clear "missing required field" error instead of silently feeding empty data to OPA.
	if err := manualPkg.ValidateSubmittedEvidence(data); err != nil {
		return evidence.Evidence{}, status, nil, fmt.Errorf("invalid evidence submission: %w", err)
	}

	// Parse submitted evidence
	var submitted manualPkg.SubmittedEvidence
	if err := json.Unmarshal(data, &submitted); err != nil {
		return evidence.Evidence{}, status, nil, fmt.Errorf("invalid evidence JSON: %w", err)
	}

	status.HasEvidence = true
	temporalStatus := manualPkg.ComputeTemporalStatus(&period, now, true)
	status.TemporalStatus = string(temporalStatus)

	// Build OPA evidence data based on type. attachmentBytes captures supporting
	// file contents (PDFs, screenshots) so we can mirror them into the policy
	// result bucket; nil for non-document types.
	opaData, attachmentBytes := r.buildOPAData(ctx, entry, &submitted, &period, temporalStatus)

	jsonData, marshalErr := json.Marshal(opaData)
	if marshalErr != nil {
		return evidence.Evidence{}, status, nil, fmt.Errorf("marshal OPA data: %w", marshalErr)
	}
	ev := evidence.New("manual", "manual:"+entry.ID, entry.ID+"/"+period.Key, jsonData)

	sidecar := &storage.ManualSidecar{
		EvidenceID:   entry.ID,
		Period:       period.Key,
		ResourceType: "manual:" + entry.ID,
		EvidenceJSON: data,
		Attachments:  attachmentBytes,
	}
	return ev, status, sidecar, nil
}

func (r *Reader) buildOPAData(ctx context.Context, entry *manualPkg.CatalogEntry, submitted *manualPkg.SubmittedEvidence, period *manualPkg.Period, temporalStatus manualPkg.TemporalStatus) (map[string]interface{}, map[string][]byte) {
	opaData := map[string]interface{}{
		"evidence_id":     entry.ID,
		"type":            string(entry.Type),
		"status":          "uploaded",
		"period":          period.Key,
		"temporal_status": string(temporalStatus),
		"hash_verified":   true,
		"completed_by":    submitted.CompletedBy,
	}

	var attachmentBytes map[string][]byte

	switch entry.Type {
	case manualPkg.EvidenceTypeDocumentUpload:
		files, bytes, err := r.verifyAttachments(ctx, entry, submitted, period)
		if err != nil {
			opaData["hash_verified"] = false
		}
		opaData["files"] = files
		attachmentBytes = bytes

	case manualPkg.EvidenceTypeChecklist:
		items := make([]map[string]interface{}, len(submitted.Items))
		for i, item := range submitted.Items {
			// Enrich with catalog info
			catalogItem := findChecklistItem(entry.Items, item.ID)
			itemData := map[string]interface{}{
				"id":      item.ID,
				"checked": item.Checked,
			}
			if catalogItem != nil {
				itemData["text"] = catalogItem.Text
				itemData["required"] = catalogItem.Required
			}
			if item.Notes != "" {
				itemData["notes"] = item.Notes
			}
			items[i] = itemData
		}
		opaData["items"] = items

	case manualPkg.EvidenceTypeDeclaration:
		opaData["declaration_text"] = submitted.DeclarationText
		if submitted.Accepted != nil {
			opaData["accepted"] = *submitted.Accepted
		}
	}

	return opaData, attachmentBytes
}

func (r *Reader) verifyAttachments(ctx context.Context, entry *manualPkg.CatalogEntry, submitted *manualPkg.SubmittedEvidence, period *manualPkg.Period) ([]map[string]interface{}, map[string][]byte, error) {
	files := make([]map[string]interface{}, 0, len(submitted.Attachments))
	var verifyErr error
	bytesByName := make(map[string][]byte, len(submitted.Attachments))

	for _, attachment := range submitted.Attachments {
		attachPath := filepath.Join(r.framework, entry.ID, period.Key, attachment)
		attachData, err := r.backend.Get(ctx, attachPath)

		fileInfo := map[string]interface{}{
			"name": attachment,
		}

		if err != nil {
			fileInfo["error"] = "not_found"
			verifyErr = fmt.Errorf("attachment not found: %s", attachment)
		} else {
			hash := sha256.Sum256(attachData)
			fileInfo["sha256"] = hex.EncodeToString(hash[:])
			fileInfo["size_bytes"] = len(attachData)
			fileInfo["format"] = filepath.Ext(attachment)
			bytesByName[attachment] = attachData
		}

		files = append(files, fileInfo)
	}

	return files, bytesByName, verifyErr
}

func findChecklistItem(items []manualPkg.ChecklistItem, id string) *manualPkg.ChecklistItem {
	for i := range items {
		if items[i].ID == id {
			return &items[i]
		}
	}
	return nil
}
