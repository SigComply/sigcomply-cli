// Package config provides configuration loading and validation for SigComply CLI.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const envTrue = "true"

// SupportedFrameworks lists valid compliance frameworks.
var SupportedFrameworks = []string{"soc2", "hipaa", "iso27001"}

// SupportedOutputFormats lists valid output formats.
var SupportedOutputFormats = []string{"text", "json", "sarif", "junit"}

// SupportedSeverities lists valid severity levels for fail_severity.
var SupportedSeverities = []string{"low", "medium", "high", "critical"}

// GitHubConfig holds GitHub provider settings (non-secret only).
// Credentials come from GITHUB_TOKEN environment variable.
type GitHubConfig struct {
	Org string `yaml:"org,omitempty" json:"org,omitempty"`
}

// CIConfig holds CI/CD behavior settings from the config file.
type CIConfig struct {
	FailOnViolation *bool  `yaml:"fail_on_violation,omitempty" json:"fail_on_violation,omitempty"`
	FailSeverity    string `yaml:"fail_severity,omitempty" json:"fail_severity,omitempty"`
}

// OutputConfig holds output settings from the config file.
type OutputConfig struct {
	Format  string `yaml:"format,omitempty" json:"format,omitempty"`
	Verbose *bool  `yaml:"verbose,omitempty" json:"verbose,omitempty"`
}

// CloudConfig holds cloud settings from the config file.
type CloudConfig struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// LocalStorageConfig holds local storage settings from the config file.
type LocalStorageConfig struct {
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}

// S3StorageConfig holds S3 storage settings from the config file.
//
// Endpoint and ForcePathStyle are used for S3-compatible on-prem stores
// (MinIO, Ceph, Dell ECS, NetApp StorageGRID). Auth optionally selects an
// explicit credential strategy (ambient or oidc).
type S3StorageConfig struct {
	Bucket         string                 `yaml:"bucket,omitempty" json:"bucket,omitempty"`
	Region         string                 `yaml:"region,omitempty" json:"region,omitempty"`
	Prefix         string                 `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Endpoint       string                 `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	ForcePathStyle bool                   `yaml:"force_path_style,omitempty" json:"force_path_style,omitempty"`
	Auth           *StorageAuthFileConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// StorageAuthFileConfig holds the auth stanza for cloud storage backends as
// it appears in the YAML config file. Mirrors storage.AuthConfig.
type StorageAuthFileConfig struct {
	Mode                     string `yaml:"mode,omitempty" json:"mode,omitempty"`
	Audience                 string `yaml:"audience,omitempty" json:"audience,omitempty"`
	RoleARN                  string `yaml:"role_arn,omitempty" json:"role_arn,omitempty"`
	SessionName              string `yaml:"session_name,omitempty" json:"session_name,omitempty"`
	WorkloadIdentityProvider string `yaml:"workload_identity_provider,omitempty" json:"workload_identity_provider,omitempty"`
	ServiceAccount           string `yaml:"service_account,omitempty" json:"service_account,omitempty"`
	TenantID                 string `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ClientID                 string `yaml:"client_id,omitempty" json:"client_id,omitempty"`
}

// GCSStorageConfig holds Google Cloud Storage settings from the config file.
type GCSStorageConfig struct {
	Bucket    string                 `yaml:"bucket,omitempty" json:"bucket,omitempty"`
	Prefix    string                 `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	ProjectID string                 `yaml:"project_id,omitempty" json:"project_id,omitempty"`
	Auth      *StorageAuthFileConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// AzureBlobStorageConfig holds Azure Blob Storage settings from the config file.
type AzureBlobStorageConfig struct {
	Account   string                 `yaml:"account,omitempty" json:"account,omitempty"`
	Container string                 `yaml:"container,omitempty" json:"container,omitempty"`
	Prefix    string                 `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Endpoint  string                 `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Auth      *StorageAuthFileConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// FileStorageConfig holds storage settings as they appear in the YAML file.
type FileStorageConfig struct {
	Enabled   *bool                   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Backend   string                  `yaml:"backend,omitempty" json:"backend,omitempty"`
	Local     *LocalStorageConfig     `yaml:"local,omitempty" json:"local,omitempty"`
	S3        *S3StorageConfig        `yaml:"s3,omitempty" json:"s3,omitempty"`
	GCS       *GCSStorageConfig       `yaml:"gcs,omitempty" json:"gcs,omitempty"`
	AzureBlob *AzureBlobStorageConfig `yaml:"azure_blob,omitempty" json:"azure_blob,omitempty"`
}

// fileConfig mirrors Config with YAML-friendly structure for file parsing.
// Provider sections hold non-secret config only. Credentials come from environment.
type fileConfig struct {
	Framework      string                    `yaml:"framework,omitempty"`
	Policies       []string                  `yaml:"policies,omitempty"`
	Controls       []string                  `yaml:"controls,omitempty"`
	AWS            *AWSConfig                `yaml:"aws,omitempty"`
	GCP            *GCPConfig                `yaml:"gcp,omitempty"`
	GitHub         *GitHubConfig             `yaml:"github,omitempty"`
	Output         *OutputConfig             `yaml:"output,omitempty"`
	CI             *CIConfig                 `yaml:"ci,omitempty"`
	Storage        *FileStorageConfig        `yaml:"storage,omitempty"`
	Cloud          *CloudConfig              `yaml:"cloud,omitempty"`
	ManualEvidence *FileManualEvidenceConfig `yaml:"manual_evidence,omitempty"`
}

// ManualEvidenceConfig holds manual evidence collection settings.
type ManualEvidenceConfig struct {
	Enabled bool   `json:"enabled"`
	Prefix  string `json:"prefix,omitempty"` // defaults to "manual-evidence/"
}

// FileManualEvidenceConfig holds manual evidence settings as they appear in the YAML file.
type FileManualEvidenceConfig struct {
	Enabled *bool  `yaml:"enabled,omitempty"`
	Prefix  string `yaml:"prefix,omitempty"`
}

// Config holds all configuration for a SigComply run.
type Config struct {
	// Core settings
	Framework       string   `json:"framework"`
	Policies        []string `json:"policies,omitempty"`
	Controls        []string `json:"controls,omitempty"`
	OutputFormat    string   `json:"output_format"`
	FailOnViolation bool     `json:"fail_on_violation"`
	FailSeverity    string   `json:"fail_severity,omitempty"`
	Verbose         bool     `json:"verbose"`

	// Cloud settings
	CloudEnabled bool `json:"cloud_enabled"`

	// Storage settings
	Storage StorageConfig `json:"storage"`

	// Manual evidence settings
	ManualEvidence ManualEvidenceConfig `json:"manual_evidence"`

	// CI/CD environment (detected at runtime, not from file)
	CI         bool   `json:"ci"`
	CIProvider string `json:"ci_provider,omitempty"`
	Repository string `json:"repository,omitempty"`
	Branch     string `json:"branch,omitempty"`
	CommitSHA  string `json:"commit_sha,omitempty"`

	// Provider settings (non-secret config only, credentials from environment)
	AWS    AWSConfig    `json:"aws"`
	GCP    GCPConfig    `json:"gcp"`
	GitHub GitHubConfig `json:"github"`

	// ConfigFile is the path to the config file that was loaded (empty if none).
	ConfigFile string `json:"-"`
}

// StorageConfig holds evidence storage settings.
type StorageConfig struct {
	Enabled bool   `json:"enabled"`
	Backend string `json:"backend"` // local, s3, gcs
	Path    string `json:"path"`    // For local backend
	Bucket  string `json:"bucket"`  // For S3 / GCS backend (object container)
	Region  string `json:"region"`  // For S3 backend
	Prefix  string `json:"prefix"`  // For S3 / GCS backend

	// Endpoint and ForcePathStyle are S3-only. Set Endpoint to an HTTPS URL
	// for on-prem S3-compatible stores (MinIO, Ceph, ECS, StorageGRID);
	// most of those also need ForcePathStyle=true.
	Endpoint       string `json:"endpoint,omitempty"`
	ForcePathStyle bool   `json:"force_path_style,omitempty"`

	// ProjectID is GCS-only. Optional — most operations don't require it
	// because bucket names are globally unique on GCS.
	ProjectID string `json:"project_id,omitempty"`

	// Account and Container are Azure-only. Account is the storage
	// account name; Container is the blob container ("bucket"
	// equivalent).
	Account   string `json:"account,omitempty"`
	Container string `json:"container,omitempty"`

	// Auth optionally configures an explicit credential strategy. When
	// Mode is empty/"ambient", the SDK default credential chain is used.
	// When Mode is "oidc", the CLI exchanges its CI OIDC token for cloud
	// credentials (AWS STS / GCP WIF / Azure federated credentials).
	Auth StorageAuthConfig `json:"auth,omitempty"`
}

// StorageAuthConfig is the runtime form of the storage auth stanza.
// All cloud-specific fields live on the same struct; only the ones relevant
// to the active backend are read.
type StorageAuthConfig struct {
	Mode     string `json:"mode,omitempty"`
	Audience string `json:"audience,omitempty"`

	// AWS-only
	RoleARN     string `json:"role_arn,omitempty"`
	SessionName string `json:"session_name,omitempty"`

	// GCP-only
	WorkloadIdentityProvider string `json:"workload_identity_provider,omitempty"`
	ServiceAccount           string `json:"service_account,omitempty"`

	// Azure-only
	TenantID string `json:"tenant_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// AWSConfig holds AWS-specific configuration (non-secret only).
// Credentials come from ambient sources (env vars, IAM role, OIDC).
type AWSConfig struct {
	Regions []string `yaml:"regions,omitempty" json:"regions,omitempty"`
}

// GCPConfig holds GCP-specific configuration (non-secret only).
// Credentials come from GOOGLE_APPLICATION_CREDENTIALS or workload identity.
type GCPConfig struct {
	ProjectID string `yaml:"project_id,omitempty" json:"project_id,omitempty"`
}

// New creates a Config with default values.
func New() *Config {
	return &Config{
		Framework:       "soc2",
		OutputFormat:    "text",
		FailOnViolation: true,
		CloudEnabled:    false,
		ManualEvidence: ManualEvidenceConfig{
			Prefix: "manual-evidence/",
		},
	}
}

// Load creates a fully initialized Config by loading from all sources.
// Precedence: defaults < config file < env vars (CLI flags applied separately).
func Load() (*Config, error) {
	cfg := New()
	cfg.LoadFromFile(findConfigFile(""))
	cfg.LoadFromEnv()
	cfg.DetectCIEnvironment()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadWithConfigPath creates a fully initialized Config using a specific config file path.
func LoadWithConfigPath(configPath string) (*Config, error) {
	cfg := New()
	cfg.LoadFromFile(findConfigFile(configPath))
	cfg.LoadFromEnv()
	cfg.DetectCIEnvironment()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// findConfigFile determines which config file to load.
// Search order: explicit path > .sigcomply.yaml in CWD > $HOME/.sigcomply.yaml.
// Returns empty string if no config file is found.
func findConfigFile(explicit string) string {
	if explicit != "" {
		return explicit
	}

	// Check CWD
	cwdPath := ".sigcomply.yaml"
	if _, err := os.Stat(cwdPath); err == nil {
		return cwdPath
	}

	// Check $HOME
	home, err := os.UserHomeDir()
	if err == nil {
		homePath := filepath.Join(home, ".sigcomply.yaml")
		if _, err := os.Stat(homePath); err == nil {
			return homePath
		}
	}

	return ""
}

// LoadFromFile loads configuration from a YAML file.
// If path is empty or the file doesn't exist, this is a no-op.
// File values override defaults but are overridden by env vars.
func (c *Config) LoadFromFile(path string) {
	if path == "" {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return
	}

	c.ConfigFile = path
	c.mergeFileConfig(&fc)
}

// mergeFileConfig merges non-zero values from a parsed file config into this Config.
func (c *Config) mergeFileConfig(fc *fileConfig) { //nolint:gocyclo // sequential field-by-field merge is inherently branchy
	if fc.Framework != "" {
		c.Framework = fc.Framework
	}

	if len(fc.Policies) > 0 {
		c.Policies = fc.Policies
	}

	if len(fc.Controls) > 0 {
		c.Controls = fc.Controls
	}

	if fc.AWS != nil && len(fc.AWS.Regions) > 0 {
		c.AWS.Regions = fc.AWS.Regions
	}

	if fc.GCP != nil && fc.GCP.ProjectID != "" {
		c.GCP.ProjectID = fc.GCP.ProjectID
	}

	if fc.GitHub != nil && fc.GitHub.Org != "" {
		c.GitHub.Org = fc.GitHub.Org
	}

	if fc.Output != nil {
		if fc.Output.Format != "" {
			c.OutputFormat = fc.Output.Format
		}
		if fc.Output.Verbose != nil {
			c.Verbose = *fc.Output.Verbose
		}
	}

	if fc.CI != nil {
		if fc.CI.FailOnViolation != nil {
			c.FailOnViolation = *fc.CI.FailOnViolation
		}
		if fc.CI.FailSeverity != "" {
			c.FailSeverity = fc.CI.FailSeverity
		}
	}

	if fc.Cloud != nil && fc.Cloud.Enabled != nil {
		c.CloudEnabled = *fc.Cloud.Enabled
	}

	if fc.Storage != nil {
		c.mergeStorageConfig(fc.Storage)
	}

	if fc.ManualEvidence != nil {
		if fc.ManualEvidence.Enabled != nil {
			c.ManualEvidence.Enabled = *fc.ManualEvidence.Enabled
		}
		if fc.ManualEvidence.Prefix != "" {
			c.ManualEvidence.Prefix = fc.ManualEvidence.Prefix
		}
	}
}

// mergeStorageConfig merges file-based storage settings into the flat StorageConfig.
func (c *Config) mergeStorageConfig(fs *FileStorageConfig) {
	if fs.Enabled != nil {
		c.Storage.Enabled = *fs.Enabled
	}
	if fs.Backend != "" {
		c.Storage.Backend = fs.Backend
	}
	if fs.Local != nil && fs.Local.Path != "" {
		c.Storage.Path = fs.Local.Path
	}
	c.mergeS3FileConfig(fs.S3)
	c.mergeGCSFileConfig(fs.GCS)
	c.mergeAzureBlobFileConfig(fs.AzureBlob)
}

// mergeS3FileConfig merges file-based S3 settings into the flat StorageConfig.
func (c *Config) mergeS3FileConfig(s3 *S3StorageConfig) {
	if s3 == nil {
		return
	}
	if s3.Bucket != "" {
		c.Storage.Bucket = s3.Bucket
	}
	if s3.Region != "" {
		c.Storage.Region = s3.Region
	}
	if s3.Prefix != "" {
		c.Storage.Prefix = s3.Prefix
	}
	if s3.Endpoint != "" {
		c.Storage.Endpoint = s3.Endpoint
	}
	if s3.ForcePathStyle {
		c.Storage.ForcePathStyle = true
	}
	if s3.Auth != nil {
		c.Storage.Auth = storageAuthFromFile(s3.Auth)
	}
}

// mergeGCSFileConfig merges file-based GCS settings into the flat StorageConfig.
func (c *Config) mergeGCSFileConfig(gcs *GCSStorageConfig) {
	if gcs == nil {
		return
	}
	if gcs.Bucket != "" {
		c.Storage.Bucket = gcs.Bucket
	}
	if gcs.Prefix != "" {
		c.Storage.Prefix = gcs.Prefix
	}
	if gcs.ProjectID != "" {
		c.Storage.ProjectID = gcs.ProjectID
	}
	if gcs.Auth != nil {
		c.Storage.Auth = storageAuthFromFile(gcs.Auth)
	}
}

// mergeAzureBlobFileConfig merges file-based Azure Blob settings into the
// flat StorageConfig.
func (c *Config) mergeAzureBlobFileConfig(az *AzureBlobStorageConfig) {
	if az == nil {
		return
	}
	if az.Account != "" {
		c.Storage.Account = az.Account
	}
	if az.Container != "" {
		c.Storage.Container = az.Container
	}
	if az.Prefix != "" {
		c.Storage.Prefix = az.Prefix
	}
	if az.Endpoint != "" {
		c.Storage.Endpoint = az.Endpoint
	}
	if az.Auth != nil {
		c.Storage.Auth = storageAuthFromFile(az.Auth)
	}
}

// storageAuthFromFile converts the file-form auth stanza into the runtime
// shape. Centralized so S3 and GCS (and Azure later) all share the same
// translation.
func storageAuthFromFile(a *StorageAuthFileConfig) StorageAuthConfig {
	return StorageAuthConfig{
		Mode:                     a.Mode,
		Audience:                 a.Audience,
		RoleARN:                  a.RoleARN,
		SessionName:              a.SessionName,
		WorkloadIdentityProvider: a.WorkloadIdentityProvider,
		ServiceAccount:           a.ServiceAccount,
		TenantID:                 a.TenantID,
		ClientID:                 a.ClientID,
	}
}

// LoadFromEnv loads configuration from environment variables.
func (c *Config) LoadFromEnv() { //nolint:gocyclo // sequential env var loading is inherently branchy
	if v := os.Getenv("SIGCOMPLY_FRAMEWORK"); v != "" {
		c.Framework = v
	}

	if v := os.Getenv("SIGCOMPLY_OUTPUT_FORMAT"); v != "" {
		c.OutputFormat = v
	}

	if os.Getenv("SIGCOMPLY_VERBOSE") == envTrue {
		c.Verbose = true
	}

	if os.Getenv("SIGCOMPLY_FAIL_ON_VIOLATION") == "false" {
		c.FailOnViolation = false
	}

	if v := os.Getenv("SIGCOMPLY_POLICIES"); v != "" {
		c.Policies = splitAndTrim(v)
	}

	if v := os.Getenv("SIGCOMPLY_CONTROLS"); v != "" {
		c.Controls = splitAndTrim(v)
	}

	// Storage configuration
	if os.Getenv("SIGCOMPLY_STORAGE_ENABLED") == envTrue {
		c.Storage.Enabled = true
	}

	if v := os.Getenv("SIGCOMPLY_STORAGE_BACKEND"); v != "" {
		c.Storage.Backend = v
	}

	if v := os.Getenv("SIGCOMPLY_STORAGE_PATH"); v != "" {
		c.Storage.Path = v
	}

	if v := os.Getenv("SIGCOMPLY_STORAGE_BUCKET"); v != "" {
		c.Storage.Bucket = v
	}

	if v := os.Getenv("SIGCOMPLY_STORAGE_REGION"); v != "" {
		c.Storage.Region = v
	}

	if v := os.Getenv("SIGCOMPLY_STORAGE_PREFIX"); v != "" {
		c.Storage.Prefix = v
	}

	if v := os.Getenv("SIGCOMPLY_STORAGE_S3_ENDPOINT"); v != "" {
		c.Storage.Endpoint = v
	}

	if os.Getenv("SIGCOMPLY_STORAGE_S3_FORCE_PATH_STYLE") == envTrue {
		c.Storage.ForcePathStyle = true
	}

	if v := os.Getenv("SIGCOMPLY_STORAGE_S3_AUTH_MODE"); v != "" {
		c.Storage.Auth.Mode = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_S3_AUTH_AUDIENCE"); v != "" {
		c.Storage.Auth.Audience = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_S3_AUTH_ROLE_ARN"); v != "" {
		c.Storage.Auth.RoleARN = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_S3_AUTH_SESSION_NAME"); v != "" {
		c.Storage.Auth.SessionName = v
	}

	// GCS-specific knobs. Bucket/Prefix re-use the generic SIGCOMPLY_STORAGE_*
	// env vars above; only GCS-only fields and the OIDC fields live here.
	if v := os.Getenv("SIGCOMPLY_STORAGE_GCS_PROJECT_ID"); v != "" {
		c.Storage.ProjectID = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_GCS_AUTH_MODE"); v != "" {
		c.Storage.Auth.Mode = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_GCS_AUTH_AUDIENCE"); v != "" {
		c.Storage.Auth.Audience = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_GCS_AUTH_WORKLOAD_IDENTITY_PROVIDER"); v != "" {
		c.Storage.Auth.WorkloadIdentityProvider = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_GCS_AUTH_SERVICE_ACCOUNT"); v != "" {
		c.Storage.Auth.ServiceAccount = v
	}

	// Azure-specific knobs.
	if v := os.Getenv("SIGCOMPLY_STORAGE_AZURE_ACCOUNT"); v != "" {
		c.Storage.Account = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_AZURE_CONTAINER"); v != "" {
		c.Storage.Container = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_AZURE_ENDPOINT"); v != "" {
		c.Storage.Endpoint = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_AZURE_AUTH_MODE"); v != "" {
		c.Storage.Auth.Mode = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_AZURE_AUTH_AUDIENCE"); v != "" {
		c.Storage.Auth.Audience = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_AZURE_AUTH_TENANT_ID"); v != "" {
		c.Storage.Auth.TenantID = v
	}
	if v := os.Getenv("SIGCOMPLY_STORAGE_AZURE_AUTH_CLIENT_ID"); v != "" {
		c.Storage.Auth.ClientID = v
	}

	// Provider settings
	if v := os.Getenv("SIGCOMPLY_GITHUB_ORG"); v != "" {
		c.GitHub.Org = v
	}

	if v := os.Getenv("SIGCOMPLY_AWS_REGION"); v != "" {
		c.AWS.Regions = []string{v}
	}

	if v := os.Getenv("SIGCOMPLY_GCP_PROJECT"); v != "" {
		c.GCP.ProjectID = v
	}

	// Manual evidence configuration
	if os.Getenv("SIGCOMPLY_MANUAL_EVIDENCE_ENABLED") == envTrue {
		c.ManualEvidence.Enabled = true
	}

	if v := os.Getenv("SIGCOMPLY_MANUAL_EVIDENCE_PREFIX"); v != "" {
		c.ManualEvidence.Prefix = v
	}
}

// DetectCIEnvironment detects if running in a CI/CD environment.
func (c *Config) DetectCIEnvironment() {
	// GitHub Actions
	if os.Getenv("GITHUB_ACTIONS") == envTrue {
		c.CI = true
		c.CIProvider = "github-actions"
		c.Repository = os.Getenv("GITHUB_REPOSITORY")
		c.Branch = os.Getenv("GITHUB_REF_NAME")
		c.CommitSHA = os.Getenv("GITHUB_SHA")
		return
	}

	// GitLab CI
	if os.Getenv("GITLAB_CI") == envTrue {
		c.CI = true
		c.CIProvider = "gitlab-ci"
		c.Repository = os.Getenv("CI_PROJECT_PATH")
		c.Branch = os.Getenv("CI_COMMIT_REF_NAME")
		c.CommitSHA = os.Getenv("CI_COMMIT_SHA")
		return
	}

	// Generic CI
	if os.Getenv("CI") == envTrue {
		c.CI = true
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if !contains(SupportedFrameworks, c.Framework) {
		return fmt.Errorf("invalid framework %q: must be one of %v", c.Framework, SupportedFrameworks)
	}

	if !contains(SupportedOutputFormats, c.OutputFormat) {
		return fmt.Errorf("invalid output format %q: must be one of %v", c.OutputFormat, SupportedOutputFormats)
	}

	// Validate fail_severity if set
	if c.FailSeverity != "" && !contains(SupportedSeverities, c.FailSeverity) {
		return fmt.Errorf("invalid fail_severity %q: must be one of %v", c.FailSeverity, SupportedSeverities)
	}

	return nil
}

// contains checks if a slice contains a value.
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// splitAndTrim splits a comma-separated string and trims whitespace from each element.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
