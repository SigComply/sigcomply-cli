// Package storage provides interfaces and implementations for evidence storage.
package storage

import (
	"context"
	"time"
)

// Backend defines the interface for evidence storage backends.
// Backends are pure key-value stores; path logic is handled by RunPath.
type Backend interface {
	// Name returns the backend identifier (e.g., "local", "s3").
	Name() string

	// Init initializes the storage backend.
	Init(ctx context.Context) error

	// StoreRaw saves raw data at the given path with optional metadata.
	StoreRaw(ctx context.Context, path string, data []byte, metadata map[string]string) (*StoredItem, error)

	// List returns stored items matching the filter.
	List(ctx context.Context, filter *ListFilter) ([]StoredItem, error)

	// Get retrieves a stored item by path.
	Get(ctx context.Context, path string) ([]byte, error)

	// URIFor returns a human-readable, fully-qualified URI for a relative
	// storage path so error messages can tell users exactly where a file
	// is expected (e.g. "s3://bucket/key", "gs://bucket/object", "file:///abs/path").
	URIFor(path string) string

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

// Config holds storage configuration.
type Config struct {
	// Backend is the storage backend type ("local", "s3", "gcs", "azure_blob").
	Backend string `yaml:"backend" json:"backend"`

	// Local contains local storage configuration.
	Local *LocalConfig `yaml:"local,omitempty" json:"local,omitempty"`

	// S3 contains S3 storage configuration. Also covers S3-compatible
	// on-prem stores when Endpoint is set.
	S3 *S3Config `yaml:"s3,omitempty" json:"s3,omitempty"`

	// GCS contains Google Cloud Storage configuration.
	GCS *GCSConfig `yaml:"gcs,omitempty" json:"gcs,omitempty"`

	// AzureBlob contains Azure Blob Storage configuration.
	AzureBlob *AzureBlobConfig `yaml:"azure_blob,omitempty" json:"azure_blob,omitempty"`
}

// GCSConfig holds Google Cloud Storage configuration.
//
// Auth mirrors the S3 model: when Auth is nil or Mode is "ambient", the
// google.golang.org/cloud SDK uses Application Default Credentials. When
// Mode is "oidc", the CLI exchanges its CI OIDC token for a federated
// access token via Workload Identity Federation.
type GCSConfig struct {
	// Bucket is the GCS bucket name.
	Bucket string `yaml:"bucket" json:"bucket"`

	// Prefix is the object name prefix for all stored items.
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`

	// ProjectID is the GCP project owning the bucket. Optional — most
	// operations don't require it because the bucket name is globally
	// unique.
	ProjectID string `yaml:"project_id,omitempty" json:"project_id,omitempty"`

	// Auth optionally specifies an explicit auth strategy.
	Auth *AuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// AzureBlobConfig holds Azure Blob Storage configuration.
//
// Auth mirrors the S3 / GCS pattern: when Auth is nil or Mode is "ambient",
// azidentity.DefaultAzureCredential is used (env vars, managed identity,
// workload identity, az CLI, etc.). When Mode is "oidc", the CLI presents
// its CI OIDC token to Azure AD as a federated client assertion.
type AzureBlobConfig struct {
	// Account is the Azure storage account name (e.g., "acmeevidence").
	Account string `yaml:"account" json:"account"`

	// Container is the blob container name (the Azure equivalent of an
	// S3 bucket).
	Container string `yaml:"container" json:"container"`

	// Prefix is the blob name prefix for all stored items.
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`

	// Endpoint overrides the default service URL
	// (https://{account}.blob.core.windows.net). Use this for sovereign
	// clouds (e.g., Azure Government) or Azurite emulators.
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`

	// Auth optionally specifies an explicit auth strategy.
	Auth *AuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// LocalConfig holds local storage configuration.
type LocalConfig struct {
	// Path is the directory path for storing evidence.
	Path string `yaml:"path" json:"path"`
}

// S3Config holds S3 storage configuration.
//
// The same struct covers AWS S3 and S3-compatible on-prem stores
// (MinIO, Ceph RadosGW, Dell ECS, NetApp StorageGRID, Pure FlashBlade).
// On-prem stores typically need Endpoint and ForcePathStyle set.
type S3Config struct {
	// Bucket is the S3 bucket name.
	Bucket string `yaml:"bucket" json:"bucket"`

	// Prefix is the key prefix for all stored items.
	Prefix string `yaml:"prefix" json:"prefix"`

	// Region is the AWS region. Required by the SDK even for on-prem stores
	// that ignore it; supply any non-empty value (e.g., "us-east-1").
	Region string `yaml:"region" json:"region"`

	// Endpoint overrides the default S3 endpoint URL. Set this for on-prem
	// S3-compatible stores (e.g., "https://minio.internal.corp:9000").
	// Leave empty for AWS S3.
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`

	// ForcePathStyle forces path-style addressing (bucket as URL path)
	// instead of virtual-hosted-style (bucket as subdomain). Required for
	// most on-prem S3-compatible stores.
	ForcePathStyle bool `yaml:"force_path_style,omitempty" json:"force_path_style,omitempty"`

	// Auth optionally specifies an explicit auth strategy. When nil or
	// when Mode is empty/"ambient", the AWS SDK default credential chain
	// is used (env vars, IAM role, EC2 instance metadata, etc.). When
	// Mode is "oidc", the CLI exchanges its CI OIDC token for temporary
	// AWS credentials via STS AssumeRoleWithWebIdentity.
	Auth *AuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// AuthMode selects the authentication strategy for a cloud storage backend.
type AuthMode string

const (
	// AuthModeAmbient (the default) lets the underlying SDK discover
	// credentials from its standard sources: environment variables, IAM
	// roles, instance metadata, GOOGLE_APPLICATION_CREDENTIALS, Azure
	// DefaultAzureCredential chain, etc.
	AuthModeAmbient AuthMode = "ambient"

	// AuthModeOIDC instructs the CLI to obtain its CI OIDC token (GitHub
	// Actions or GitLab CI) and exchange it for cloud credentials. The
	// exchange is provider-specific: STS AssumeRoleWithWebIdentity on AWS,
	// Workload Identity Federation on GCP, Azure AD federated credentials
	// on Azure.
	AuthModeOIDC AuthMode = "oidc"
)

// AuthConfig configures how a cloud storage backend authenticates.
// All cloud-specific fields live on the same struct; only those relevant
// to the backend in question are read.
type AuthConfig struct {
	// Mode selects the auth strategy. Empty defaults to AuthModeAmbient.
	Mode AuthMode `yaml:"mode,omitempty" json:"mode,omitempty"`

	// Audience is the audience claim requested when fetching the CI OIDC
	// token. Defaults are backend-specific:
	//   AWS:   "sts.amazonaws.com"
	//   GCP:   "//iam.googleapis.com/<workload_identity_provider>"
	//   Azure: "api://AzureADTokenExchange"
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty"`

	// AWS-only fields (used when Mode is "oidc" and the backend is S3).
	RoleARN     string `yaml:"role_arn,omitempty" json:"role_arn,omitempty"`
	SessionName string `yaml:"session_name,omitempty" json:"session_name,omitempty"`

	// GCP-only fields.
	WorkloadIdentityProvider string `yaml:"workload_identity_provider,omitempty" json:"workload_identity_provider,omitempty"`
	ServiceAccount           string `yaml:"service_account,omitempty" json:"service_account,omitempty"`

	// Azure-only fields.
	TenantID string `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ClientID string `yaml:"client_id,omitempty" json:"client_id,omitempty"`
}

// NewBackend creates a new storage backend based on configuration.
func NewBackend(cfg *Config) (Backend, error) {
	switch cfg.Backend {
	case "local", "":
		localCfg := cfg.Local
		if localCfg == nil {
			localCfg = &LocalConfig{Path: ".sigcomply/evidence"}
		}
		return NewLocalBackend(localCfg), nil
	case "s3":
		if cfg.S3 == nil {
			return nil, &ConfigError{Message: "S3 configuration required"}
		}
		return NewS3Backend(cfg.S3), nil
	case "gcs":
		if cfg.GCS == nil {
			return nil, &ConfigError{Message: "GCS configuration required"}
		}
		return NewGCSBackend(cfg.GCS), nil
	case "azure_blob":
		if cfg.AzureBlob == nil {
			return nil, &ConfigError{Message: "Azure Blob configuration required"}
		}
		return NewAzureBlobBackend(cfg.AzureBlob), nil
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
