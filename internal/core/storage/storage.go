// Package storage provides interfaces and implementations for evidence storage.
package storage

import (
	"context"
	"time"

	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

// Backend defines the interface for evidence storage backends.
type Backend interface {
	// Name returns the backend identifier (e.g., "local", "s3").
	Name() string

	// Init initializes the storage backend.
	Init(ctx context.Context) error

	// Store saves evidence and returns the storage location.
	Store(ctx context.Context, ev *evidence.Evidence) (*StoredItem, error)

	// StoreCheckResult saves a complete check result.
	StoreCheckResult(ctx context.Context, result *evidence.CheckResult) (*StoredItem, error)

	// List returns stored items matching the filter.
	List(ctx context.Context, filter *ListFilter) ([]StoredItem, error)

	// Get retrieves a stored item by path.
	Get(ctx context.Context, path string) ([]byte, error)

	// Close closes the storage backend.
	Close() error
}

// StoredItem represents an item stored in the backend.
type StoredItem struct {
	// Path is the storage path/key.
	Path string `json:"path"`

	// Hash is the SHA-256 hash of the stored content.
	Hash string `json:"hash"`

	// Size is the size in bytes.
	Size int64 `json:"size"`

	// StoredAt is when the item was stored.
	StoredAt time.Time `json:"stored_at"`

	// ContentType is the MIME type of the content.
	ContentType string `json:"content_type,omitempty"`

	// Metadata contains additional key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ListFilter defines filtering options for listing stored items.
type ListFilter struct {
	// Prefix filters items by path prefix.
	Prefix string

	// After filters items stored after this time.
	After time.Time

	// Before filters items stored before this time.
	Before time.Time

	// Limit limits the number of results.
	Limit int

	// Framework filters by compliance framework.
	Framework string

	// RunID filters by specific run ID.
	RunID string
}

// Manifest represents a collection of stored items for a run.
type Manifest struct {
	// RunID is the unique identifier for this run.
	RunID string `json:"run_id"`

	// Framework is the compliance framework used.
	Framework string `json:"framework"`

	// Timestamp is when the run was executed.
	Timestamp time.Time `json:"timestamp"`

	// Backend is the storage backend name.
	Backend string `json:"backend"`

	// Items lists all stored items in this run.
	Items []StoredItem `json:"items"`

	// CheckResult contains the path to the stored check result.
	CheckResult string `json:"check_result,omitempty"`

	// EvidenceCount is the total number of evidence items.
	EvidenceCount int `json:"evidence_count"`

	// TotalSize is the total size of all stored items.
	TotalSize int64 `json:"total_size"`
}

// Config holds storage configuration.
type Config struct {
	// Backend is the storage backend type (local, s3, gcs).
	Backend string `yaml:"backend" json:"backend"`

	// Local contains local storage configuration.
	Local *LocalConfig `yaml:"local,omitempty" json:"local,omitempty"`

	// S3 contains S3 storage configuration.
	S3 *S3Config `yaml:"s3,omitempty" json:"s3,omitempty"`
}

// LocalConfig holds local storage configuration.
type LocalConfig struct {
	// Path is the directory path for storing evidence.
	Path string `yaml:"path" json:"path"`
}

// S3Config holds S3 storage configuration.
type S3Config struct {
	// Bucket is the S3 bucket name.
	Bucket string `yaml:"bucket" json:"bucket"`

	// Prefix is the key prefix for all stored items.
	Prefix string `yaml:"prefix" json:"prefix"`

	// Region is the AWS region.
	Region string `yaml:"region" json:"region"`
}

// NewBackend creates a new storage backend based on configuration.
func NewBackend(cfg *Config) (Backend, error) {
	switch cfg.Backend {
	case "local", "":
		localCfg := cfg.Local
		if localCfg == nil {
			localCfg = &LocalConfig{Path: ".tracevault/evidence"}
		}
		return NewLocalBackend(localCfg), nil
	case "s3":
		if cfg.S3 == nil {
			return nil, &ConfigError{Message: "S3 configuration required"}
		}
		return NewS3Backend(cfg.S3), nil
	default:
		return nil, &ConfigError{Message: "unsupported storage backend: " + cfg.Backend}
	}
}

// ConfigError represents a storage configuration error.
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return "storage config error: " + e.Message
}
