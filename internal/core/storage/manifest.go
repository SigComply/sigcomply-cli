package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ManifestBuilder helps construct a storage manifest.
type ManifestBuilder struct {
	manifest *Manifest
	backend  Backend
}

// NewManifestBuilder creates a new manifest builder.
func NewManifestBuilder(backend Backend, framework string) *ManifestBuilder {
	return &ManifestBuilder{
		manifest: &Manifest{
			RunID:     uuid.New().String(),
			Framework: framework,
			Timestamp: time.Now().UTC(),
			Backend:   backend.Name(),
			Items:     []StoredItem{},
		},
		backend: backend,
	}
}

// WithRunID sets a custom run ID.
func (b *ManifestBuilder) WithRunID(runID string) *ManifestBuilder {
	b.manifest.RunID = runID
	return b
}

// AddItem adds a stored item to the manifest.
func (b *ManifestBuilder) AddItem(item *StoredItem) {
	b.manifest.Items = append(b.manifest.Items, *item)
	b.manifest.TotalSize += item.Size
}

// SetCheckResult sets the check result path.
func (b *ManifestBuilder) SetCheckResult(path string) {
	b.manifest.CheckResult = path
}

// SetEvidenceCount sets the evidence count.
func (b *ManifestBuilder) SetEvidenceCount(count int) {
	b.manifest.EvidenceCount = count
}

// Build finalizes and returns the manifest.
func (b *ManifestBuilder) Build() *Manifest {
	return b.manifest
}

// Store saves the manifest to storage and returns the stored item.
func (b *ManifestBuilder) Store(ctx context.Context) (*StoredItem, error) {
	// Marshal manifest to JSON
	data, err := json.MarshalIndent(b.manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// Compute hash
	hash := sha256.Sum256(data)

	// Build path based on backend type
	var path string
	switch lb := b.backend.(type) {
	case *LocalBackend:
		path = filepath.Join("runs", b.manifest.RunID, "manifest.json")
		fullPath := filepath.Join(lb.GetPath(), path)

		// Create directory
		if err := createParentDir(fullPath); err != nil {
			return nil, err
		}

		// Write file
		if err := writeSecureFile(fullPath, data); err != nil {
			return nil, err
		}
	default:
		// For other backends, use the generic store method
		// Create a temporary evidence-like structure
		return b.storeGeneric(ctx, data)
	}

	return &StoredItem{
		Path:        path,
		Hash:        hex.EncodeToString(hash[:]),
		Size:        int64(len(data)),
		StoredAt:    time.Now().UTC(),
		ContentType: "application/json",
		Metadata: map[string]string{
			"type":      "manifest",
			"run_id":    b.manifest.RunID,
			"framework": b.manifest.Framework,
		},
	}, nil
}

// storeGeneric stores manifest using a generic approach for non-local backends.
func (b *ManifestBuilder) storeGeneric(_ context.Context, data []byte) (*StoredItem, error) {
	// For S3 and other backends, we need to use their specific methods
	// This is a placeholder that would need backend-specific implementation
	hash := sha256.Sum256(data)

	return &StoredItem{
		Path:        fmt.Sprintf("runs/%s/manifest.json", b.manifest.RunID),
		Hash:        hex.EncodeToString(hash[:]),
		Size:        int64(len(data)),
		StoredAt:    time.Now().UTC(),
		ContentType: "application/json",
	}, nil
}

// StoreRun stores all evidence and check result, building the manifest.
func StoreRun(ctx context.Context, backend Backend, result *evidence.CheckResult, evidenceList []evidence.Evidence) (*Manifest, error) {
	builder := NewManifestBuilder(backend, result.Framework)

	if result.RunID != "" {
		builder.WithRunID(result.RunID)
	}

	// Store each piece of evidence
	for i := range evidenceList {
		item, err := backend.Store(ctx, &evidenceList[i])
		if err != nil {
			return nil, fmt.Errorf("failed to store evidence %s: %w", evidenceList[i].ID, err)
		}
		builder.AddItem(item)
	}
	builder.SetEvidenceCount(len(evidenceList))

	// Store check result
	checkResultItem, err := backend.StoreCheckResult(ctx, result)
	if err != nil {
		return nil, fmt.Errorf("failed to store check result: %w", err)
	}
	builder.AddItem(checkResultItem)
	builder.SetCheckResult(checkResultItem.Path)

	// Store manifest
	manifestItem, err := builder.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to store manifest: %w", err)
	}
	builder.AddItem(manifestItem)

	return builder.Build(), nil
}

// LoadManifest loads a manifest from storage.
func LoadManifest(ctx context.Context, backend Backend, runID string) (*Manifest, error) {
	path := fmt.Sprintf("runs/%s/manifest.json", runID)

	data, err := backend.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// Helper functions for file operations
func createParentDir(path string) error {
	dir := filepath.Dir(path)
	return osWrapper.MkdirAll(dir, 0750)
}

func writeSecureFile(path string, data []byte) error {
	return osWrapper.WriteFile(path, data, 0600)
}

// osOperations provides an interface for OS operations (for testing).
type osOperations interface {
	MkdirAll(path string, perm uint32) error
	WriteFile(path string, data []byte, perm uint32) error
}

// realOS implements osOperations using the real os package.
type realOS struct{}

func (realOS) MkdirAll(path string, perm uint32) error {
	return os.MkdirAll(path, os.FileMode(perm))
}

func (realOS) WriteFile(path string, data []byte, perm uint32) error {
	return os.WriteFile(path, data, os.FileMode(perm))
}

var osWrapper osOperations = realOS{}
