package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LocalBackend implements storage using the local filesystem.
type LocalBackend struct {
	config *LocalConfig
	path   string
}

// NewLocalBackend creates a new local storage backend.
func NewLocalBackend(cfg *LocalConfig) *LocalBackend {
	return &LocalBackend{
		config: cfg,
		path:   cfg.Path,
	}
}

// Name returns the backend identifier.
func (b *LocalBackend) Name() string {
	return "local"
}

// Init initializes the local storage backend by creating the directory.
func (b *LocalBackend) Init(ctx context.Context) error {
	// Expand home directory if needed
	if strings.HasPrefix(b.path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		b.path = filepath.Join(home, b.path[2:])
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(b.path, 0750); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	return nil
}

// StoreRaw saves raw data to local storage at the given path.
func (b *LocalBackend) StoreRaw(_ context.Context, path string, data []byte, metadata map[string]string) (*StoredItem, error) {
	fullPath := filepath.Join(b.path, path)

	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(fullPath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	// Compute hash
	hash := sha256.Sum256(data)

	return &StoredItem{
		Path:        path,
		Hash:        hex.EncodeToString(hash[:]),
		Size:        int64(len(data)),
		StoredAt:    time.Now().UTC(),
		ContentType: "application/json",
		Metadata:    metadata,
	}, nil
}

// List returns stored items matching the filter.
func (b *LocalBackend) List(ctx context.Context, filter *ListFilter) ([]StoredItem, error) {
	var items []StoredItem

	searchPath := b.path
	if filter != nil && filter.Prefix != "" {
		searchPath = filepath.Join(b.path, filter.Prefix)
	}

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, walkErr error) error {
		// Skip inaccessible files
		if walkErr != nil || info.IsDir() {
			return nil //nolint:nilerr // intentionally skip errors for inaccessible files
		}

		item, skip := b.processListItem(path, info, filter)
		if skip {
			return nil
		}
		if item != nil {
			items = append(items, *item)
		}

		// Apply limit
		if filter != nil && filter.Limit > 0 && len(items) >= filter.Limit {
			return filepath.SkipAll
		}

		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}

	return items, nil
}

// processListItem processes a single file for listing.
// Returns the item and whether to skip it.
func (b *LocalBackend) processListItem(path string, info os.FileInfo, filter *ListFilter) (*StoredItem, bool) {
	// Get relative path
	relPath, err := filepath.Rel(b.path, path)
	if err != nil {
		return nil, true
	}

	// Apply time filters
	modTime := info.ModTime()
	if filter != nil {
		if !filter.After.IsZero() && modTime.Before(filter.After) {
			return nil, true
		}
		if !filter.Before.IsZero() && modTime.After(filter.Before) {
			return nil, true
		}
	}

	// Read file to compute hash
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, true
	}
	hash := sha256.Sum256(data)

	return &StoredItem{
		Path:     relPath,
		Hash:     hex.EncodeToString(hash[:]),
		Size:     info.Size(),
		StoredAt: modTime,
	}, false
}

// Get retrieves a stored item by path.
func (b *LocalBackend) Get(ctx context.Context, path string) ([]byte, error) {
	fullPath := filepath.Join(b.path, path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &NotFoundError{Path: path}
		}
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return data, nil
}

// Close closes the local storage backend (no-op for local).
func (b *LocalBackend) Close() error {
	return nil
}

// GetPath returns the base path for the local backend.
func (b *LocalBackend) GetPath() string {
	return b.path
}

// NotFoundError is returned when a stored item is not found.
type NotFoundError struct {
	Path string
}

func (e *NotFoundError) Error() string {
	return "item not found: " + e.Path
}

