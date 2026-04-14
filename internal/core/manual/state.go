package manual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
)

// ExecutionState tracks what manual evidence has been attested across runs.
type ExecutionState struct {
	SchemaVersion string                             `json:"schema_version"`
	Framework     string                             `json:"framework"`
	LastUpdated   time.Time                          `json:"last_updated"`
	Manual        map[string]map[string]Entry `json:"manual"` // evidence_id → period → entry
}

// Entry records the status of a single piece of manual evidence.
type Entry struct {
	Status       string            `json:"status"`                  // "uploaded", "attested"
	Files        []string          `json:"files"`
	FileHashes   map[string]string `json:"file_hashes"`
	AttestedAt   *time.Time        `json:"attested_at,omitempty"`
	RunID        string            `json:"run_id,omitempty"`
	PolicyStatus string            `json:"policy_status,omitempty"`
}

// NewExecutionState creates a new empty execution state.
func NewExecutionState(framework string) *ExecutionState {
	return &ExecutionState{
		SchemaVersion: "1.0",
		Framework:     framework,
		LastUpdated:   time.Now().UTC(),
		Manual:        make(map[string]map[string]Entry),
	}
}

// LoadState loads the execution state from storage. Returns an empty state if not found.
func LoadState(ctx context.Context, backend storage.Backend, path string) (*ExecutionState, error) {
	data, err := backend.Get(ctx, path)
	if err != nil {
		var notFound *storage.NotFoundError
		if errors.As(err, &notFound) {
			return &ExecutionState{
				SchemaVersion: "1.0",
				Manual:        make(map[string]map[string]Entry),
			}, nil
		}
		return nil, fmt.Errorf("failed to load execution state: %w", err)
	}

	var state ExecutionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse execution state: %w", err)
	}

	if state.Manual == nil {
		state.Manual = make(map[string]map[string]Entry)
	}

	return &state, nil
}

// Save persists the execution state to storage.
func (s *ExecutionState) Save(ctx context.Context, backend storage.Backend, path string) error {
	s.LastUpdated = time.Now().UTC()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal execution state: %w", err)
	}

	_, err = backend.StoreRaw(ctx, path, data, nil)
	if err != nil {
		return fmt.Errorf("failed to save execution state: %w", err)
	}

	return nil
}

// IsAttested returns true if the given evidence ID and period has been attested.
func (s *ExecutionState) IsAttested(evidenceID, period string) bool {
	periods, ok := s.Manual[evidenceID]
	if !ok {
		return false
	}
	entry, ok := periods[period]
	if !ok {
		return false
	}
	return entry.Status == "attested"
}

// RecordAttestation records that a piece of manual evidence has been processed.
func (s *ExecutionState) RecordAttestation(evidenceID, period, runID, status string, fileHashes map[string]string) {
	if s.Manual == nil {
		s.Manual = make(map[string]map[string]Entry)
	}
	if s.Manual[evidenceID] == nil {
		s.Manual[evidenceID] = make(map[string]Entry)
	}

	now := time.Now().UTC()
	files := make([]string, 0, len(fileHashes))
	for f := range fileHashes {
		files = append(files, f)
	}

	s.Manual[evidenceID][period] = Entry{
		Status:       status,
		Files:        files,
		FileHashes:   fileHashes,
		AttestedAt:   &now,
		RunID:        runID,
		PolicyStatus: status,
	}
}
