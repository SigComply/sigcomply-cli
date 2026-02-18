// Package config provides configuration loading and validation for SigComply CLI.
package config

import (
	"fmt"
	"os"
	"path/filepath"

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
type S3StorageConfig struct {
	Bucket string `yaml:"bucket,omitempty" json:"bucket,omitempty"`
	Region string `yaml:"region,omitempty" json:"region,omitempty"`
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
}

// FileStorageConfig holds storage settings as they appear in the YAML file.
type FileStorageConfig struct {
	Enabled *bool               `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Backend string              `yaml:"backend,omitempty" json:"backend,omitempty"`
	Local   *LocalStorageConfig `yaml:"local,omitempty" json:"local,omitempty"`
	S3      *S3StorageConfig    `yaml:"s3,omitempty" json:"s3,omitempty"`
}

// fileConfig mirrors Config with YAML-friendly structure for file parsing.
// Provider sections hold non-secret config only. Credentials come from environment.
type fileConfig struct {
	Framework string             `yaml:"framework,omitempty"`
	AWS       *AWSConfig         `yaml:"aws,omitempty"`
	GitHub    *GitHubConfig      `yaml:"github,omitempty"`
	Output    *OutputConfig      `yaml:"output,omitempty"`
	CI        *CIConfig          `yaml:"ci,omitempty"`
	Storage   *FileStorageConfig `yaml:"storage,omitempty"`
	Cloud     *CloudConfig       `yaml:"cloud,omitempty"`
}

// Config holds all configuration for a SigComply run.
type Config struct {
	// Core settings
	Framework       string `json:"framework"`
	OutputFormat    string `json:"output_format"`
	FailOnViolation bool   `json:"fail_on_violation"`
	FailSeverity    string `json:"fail_severity,omitempty"`
	Verbose         bool   `json:"verbose"`

	// Cloud settings
	CloudEnabled bool   `json:"cloud_enabled"`
	APIToken     string `json:"-"` // Never serialize

	// Storage settings
	Storage StorageConfig `json:"storage"`

	// CI/CD environment (detected at runtime, not from file)
	CI         bool   `json:"ci"`
	CIProvider string `json:"ci_provider,omitempty"`
	Repository string `json:"repository,omitempty"`
	Branch     string `json:"branch,omitempty"`
	CommitSHA  string `json:"commit_sha,omitempty"`

	// Provider settings (non-secret config only, credentials from environment)
	AWS    AWSConfig    `json:"aws"`
	GitHub GitHubConfig `json:"github"`

	// ConfigFile is the path to the config file that was loaded (empty if none).
	ConfigFile string `json:"-"`
}

// StorageConfig holds evidence storage settings.
type StorageConfig struct {
	Enabled bool   `json:"enabled"`
	Backend string `json:"backend"` // local, s3
	Path    string `json:"path"`    // For local backend
	Bucket  string `json:"bucket"`  // For S3 backend
	Region  string `json:"region"`  // For S3 backend
	Prefix  string `json:"prefix"`  // For S3 backend
}

// AWSConfig holds AWS-specific configuration (non-secret only).
// Credentials come from ambient sources (env vars, IAM role, OIDC).
type AWSConfig struct {
	Regions []string `yaml:"regions,omitempty" json:"regions,omitempty"`
}

// New creates a Config with default values.
func New() *Config {
	return &Config{
		Framework:       "soc2",
		OutputFormat:    "text",
		FailOnViolation: true,
		CloudEnabled:    false,
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
func (c *Config) mergeFileConfig(fc *fileConfig) {
	if fc.Framework != "" {
		c.Framework = fc.Framework
	}

	if fc.AWS != nil && len(fc.AWS.Regions) > 0 {
		c.AWS.Regions = fc.AWS.Regions
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
	if fs.S3 != nil {
		if fs.S3.Bucket != "" {
			c.Storage.Bucket = fs.S3.Bucket
		}
		if fs.S3.Region != "" {
			c.Storage.Region = fs.S3.Region
		}
		if fs.S3.Prefix != "" {
			c.Storage.Prefix = fs.S3.Prefix
		}
	}
}

// LoadFromEnv loads configuration from environment variables.
func (c *Config) LoadFromEnv() {
	if v := os.Getenv("SIGCOMPLY_FRAMEWORK"); v != "" {
		c.Framework = v
	}

	if v := os.Getenv("SIGCOMPLY_OUTPUT_FORMAT"); v != "" {
		c.OutputFormat = v
	}

	if v := os.Getenv("SIGCOMPLY_API_TOKEN"); v != "" {
		c.APIToken = v
		c.CloudEnabled = true
	}

	if os.Getenv("SIGCOMPLY_VERBOSE") == envTrue {
		c.Verbose = true
	}

	if os.Getenv("SIGCOMPLY_FAIL_ON_VIOLATION") == "false" {
		c.FailOnViolation = false
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

	// Provider settings
	if v := os.Getenv("SIGCOMPLY_GITHUB_ORG"); v != "" {
		c.GitHub.Org = v
	}

	if v := os.Getenv("SIGCOMPLY_AWS_REGION"); v != "" {
		c.AWS.Regions = []string{v}
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
