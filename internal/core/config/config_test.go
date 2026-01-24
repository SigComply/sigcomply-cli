package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := New()

	assert.Equal(t, "soc2", cfg.Framework)
	assert.Equal(t, "text", cfg.OutputFormat)
	assert.False(t, cfg.CloudEnabled)
	assert.True(t, cfg.FailOnViolation)
}

func TestConfig_LoadFromEnv(t *testing.T) {
	// Use t.Setenv which automatically cleans up after the test
	t.Setenv("SIGCOMPLY_FRAMEWORK", "hipaa")
	t.Setenv("SIGCOMPLY_OUTPUT_FORMAT", "json")
	t.Setenv("SIGCOMPLY_API_TOKEN", "test-token")

	cfg := New()
	cfg.LoadFromEnv()

	assert.Equal(t, "hipaa", cfg.Framework)
	assert.Equal(t, "json", cfg.OutputFormat)
	assert.True(t, cfg.CloudEnabled, "CloudEnabled should be true when API token is set")
}

func TestConfig_DetectCIEnvironment(t *testing.T) {
	tests := []struct {
		name         string
		envVars      map[string]string
		wantCI       bool
		wantProvider string
	}{
		{
			name:         "GitHub Actions",
			envVars:      map[string]string{"GITHUB_ACTIONS": "true"},
			wantCI:       true,
			wantProvider: "github-actions",
		},
		{
			name:         "GitLab CI",
			envVars:      map[string]string{"GITLAB_CI": "true"},
			wantCI:       true,
			wantProvider: "gitlab-ci",
		},
		{
			name:         "Generic CI",
			envVars:      map[string]string{"CI": "true"},
			wantCI:       true,
			wantProvider: "",
		},
		{
			name:         "No CI",
			envVars:      map[string]string{},
			wantCI:       false,
			wantProvider: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear CI env vars using t.Setenv with empty string
			// and save original for restoration
			ciVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"}
			for _, v := range ciVars {
				// Save original and clear
				if orig := os.Getenv(v); orig != "" {
					t.Setenv(v, "") // Will restore after test
				}
				os.Unsetenv(v) //nolint:errcheck // Unset is best effort in tests
			}

			// Set test env vars
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg := New()
			cfg.DetectCIEnvironment()

			assert.Equal(t, tt.wantCI, cfg.CI)
			assert.Equal(t, tt.wantProvider, cfg.CIProvider)
		})
	}
}

func TestConfig_ValidateFramework(t *testing.T) {
	tests := []struct {
		framework string
		valid     bool
	}{
		{"soc2", true},
		{"hipaa", true},
		{"iso27001", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.framework, func(t *testing.T) {
			cfg := New()
			cfg.Framework = tt.framework

			err := cfg.Validate()
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestConfig_ValidateOutputFormat(t *testing.T) {
	tests := []struct {
		format string
		valid  bool
	}{
		{"text", true},
		{"json", true},
		{"sarif", true},
		{"junit", true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			cfg := New()
			cfg.OutputFormat = tt.format

			err := cfg.Validate()
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestConfig_AWSRegions(t *testing.T) {
	cfg := New()

	// Default should auto-detect (empty)
	assert.Empty(t, cfg.AWS.Regions)

	// Set regions
	cfg.AWS.Regions = []string{"us-east-1", "us-west-2"}
	assert.Len(t, cfg.AWS.Regions, 2)
}

func TestLoad_Integration(t *testing.T) {
	// Use t.Setenv to ensure clean environment
	// First unset the API token if it exists
	os.Unsetenv("SIGCOMPLY_API_TOKEN") //nolint:errcheck // Best effort cleanup

	cfg, err := Load()
	require.NoError(t, err)

	// Should have defaults
	assert.Equal(t, "soc2", cfg.Framework)
	assert.Equal(t, "text", cfg.OutputFormat)
}
