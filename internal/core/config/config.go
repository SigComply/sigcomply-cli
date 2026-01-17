// Package config provides configuration loading and validation for TraceVault CLI.
package config

import (
	"fmt"
	"os"
)

const envTrue = "true"

// SupportedFrameworks lists valid compliance frameworks.
var SupportedFrameworks = []string{"soc2", "hipaa", "iso27001"}

// SupportedOutputFormats lists valid output formats.
var SupportedOutputFormats = []string{"text", "json", "sarif", "junit"}

// Config holds all configuration for a TraceVault run.
type Config struct {
	// Core settings
	Framework       string `json:"framework"`
	OutputFormat    string `json:"output_format"`
	FailOnViolation bool   `json:"fail_on_violation"`
	Verbose         bool   `json:"verbose"`

	// Cloud settings
	CloudEnabled bool   `json:"cloud_enabled"`
	APIToken     string `json:"-"` // Never serialize

	// CI/CD environment
	CI         bool   `json:"ci"`
	CIProvider string `json:"ci_provider,omitempty"`
	Repository string `json:"repository,omitempty"`
	Branch     string `json:"branch,omitempty"`
	CommitSHA  string `json:"commit_sha,omitempty"`

	// Collector settings
	AWS AWSConfig `json:"aws"`
}

// AWSConfig holds AWS-specific configuration.
type AWSConfig struct {
	Regions []string `json:"regions,omitempty"`
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
func Load() (*Config, error) {
	cfg := New()
	cfg.LoadFromEnv()
	cfg.DetectCIEnvironment()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadFromEnv loads configuration from environment variables.
func (c *Config) LoadFromEnv() {
	if v := os.Getenv("TRACEVAULT_FRAMEWORK"); v != "" {
		c.Framework = v
	}

	if v := os.Getenv("TRACEVAULT_OUTPUT_FORMAT"); v != "" {
		c.OutputFormat = v
	}

	if v := os.Getenv("TRACEVAULT_API_TOKEN"); v != "" {
		c.APIToken = v
		c.CloudEnabled = true
	}

	if os.Getenv("TRACEVAULT_VERBOSE") == envTrue {
		c.Verbose = true
	}

	if os.Getenv("TRACEVAULT_FAIL_ON_VIOLATION") == "false" {
		c.FailOnViolation = false
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
