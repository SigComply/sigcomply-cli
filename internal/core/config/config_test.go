package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testFrameworkISO = "framework: iso27001"

func TestConfig_Defaults(t *testing.T) {
	cfg := New()

	assert.Equal(t, "soc2", cfg.Framework)
	assert.Equal(t, "text", cfg.OutputFormat)
	assert.False(t, cfg.CloudEnabled)
	assert.True(t, cfg.FailOnViolation)
}

func TestConfig_LoadFromEnv(t *testing.T) {
	t.Setenv("SIGCOMPLY_FRAMEWORK", "hipaa")
	t.Setenv("SIGCOMPLY_OUTPUT_FORMAT", "json")

	cfg := New()
	cfg.LoadFromEnv()

	assert.Equal(t, "hipaa", cfg.Framework)
	assert.Equal(t, "json", cfg.OutputFormat)
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
			ciVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"}
			for _, v := range ciVars {
				if orig := os.Getenv(v); orig != "" {
					t.Setenv(v, "")
				}
				os.Unsetenv(v) //nolint:errcheck // Unset is best effort in tests
			}

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
	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "soc2", cfg.Framework)
	assert.Equal(t, "text", cfg.OutputFormat)
}

func TestConfig_LoadFromFile_FullConfig(t *testing.T) {
	content := `
framework: iso27001

aws:
  regions:
    - us-east-1
    - eu-west-1

github:
  org: my-org

output:
  format: json
  verbose: true

ci:
  fail_on_violation: false
  fail_severity: high

storage:
  enabled: true
  backend: s3
  s3:
    bucket: my-bucket
    region: us-east-1
    prefix: compliance/

cloud:
  enabled: true
`
	path := writeTestFile(t, content)

	cfg := New()
	cfg.LoadFromFile(path)

	assert.Equal(t, path, cfg.ConfigFile)
	assert.Equal(t, "iso27001", cfg.Framework)
	assert.Equal(t, "json", cfg.OutputFormat)
	assert.True(t, cfg.Verbose)
	assert.False(t, cfg.FailOnViolation)
	assert.Equal(t, "high", cfg.FailSeverity)
	assert.True(t, cfg.CloudEnabled)

	// Provider config
	assert.Equal(t, []string{"us-east-1", "eu-west-1"}, cfg.AWS.Regions)
	assert.Equal(t, "my-org", cfg.GitHub.Org)

	// Storage
	assert.True(t, cfg.Storage.Enabled)
	assert.Equal(t, "s3", cfg.Storage.Backend)
	assert.Equal(t, "my-bucket", cfg.Storage.Bucket)
	assert.Equal(t, "us-east-1", cfg.Storage.Region)
	assert.Equal(t, "compliance/", cfg.Storage.Prefix)
}

func TestConfig_LoadFromFile_LocalStorage(t *testing.T) {
	content := `
storage:
  enabled: true
  backend: local
  local:
    path: ./my-evidence
`
	path := writeTestFile(t, content)

	cfg := New()
	cfg.LoadFromFile(path)

	assert.True(t, cfg.Storage.Enabled)
	assert.Equal(t, "local", cfg.Storage.Backend)
	assert.Equal(t, "./my-evidence", cfg.Storage.Path)
}

func TestConfig_LoadFromFile_MinimalConfig(t *testing.T) {
	path := writeTestFile(t, testFrameworkISO)

	cfg := New()
	cfg.LoadFromFile(path)

	assert.Equal(t, "iso27001", cfg.Framework)
	// Defaults preserved
	assert.Equal(t, "text", cfg.OutputFormat)
	assert.True(t, cfg.FailOnViolation)
}

func TestConfig_LoadFromFile_EmptyPath(t *testing.T) {
	cfg := New()
	cfg.LoadFromFile("")

	assert.Equal(t, "soc2", cfg.Framework)
	assert.Empty(t, cfg.ConfigFile)
}

func TestConfig_LoadFromFile_FileNotFound(t *testing.T) {
	cfg := New()
	cfg.LoadFromFile("/nonexistent/path.yaml")

	assert.Equal(t, "soc2", cfg.Framework)
	assert.Empty(t, cfg.ConfigFile)
}

func TestConfig_LoadFromFile_InvalidYAML(t *testing.T) {
	path := writeTestFile(t, "{{{{invalid yaml")

	cfg := New()
	cfg.LoadFromFile(path)

	assert.Equal(t, "soc2", cfg.Framework)
	assert.Empty(t, cfg.ConfigFile)
}

func TestConfig_Precedence_FileOverridesDefaults(t *testing.T) {
	path := writeTestFile(t, testFrameworkISO)

	cfg := New()
	assert.Equal(t, "soc2", cfg.Framework) // default

	cfg.LoadFromFile(path)
	assert.Equal(t, "iso27001", cfg.Framework) // file overrides default
}

func TestConfig_Precedence_EnvOverridesFile(t *testing.T) {
	path := writeTestFile(t, testFrameworkISO)

	t.Setenv("SIGCOMPLY_FRAMEWORK", "hipaa")

	cfg := New()
	cfg.LoadFromFile(path)
	assert.Equal(t, "iso27001", cfg.Framework) // file value

	cfg.LoadFromEnv()
	assert.Equal(t, "hipaa", cfg.Framework) // env overrides file
}

func TestConfig_Precedence_EnvOverridesFile_OutputFormat(t *testing.T) {
	content := `
output:
  format: sarif
`
	path := writeTestFile(t, content)

	t.Setenv("SIGCOMPLY_OUTPUT_FORMAT", "json")

	cfg := New()
	cfg.LoadFromFile(path)
	assert.Equal(t, "sarif", cfg.OutputFormat) // file value

	cfg.LoadFromEnv()
	assert.Equal(t, "json", cfg.OutputFormat) // env overrides file
}

func TestConfig_ValidateFailSeverity(t *testing.T) {
	tests := []struct {
		severity string
		valid    bool
	}{
		{"", true},
		{"low", true},
		{"medium", true},
		{"high", true},
		{"critical", true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			cfg := New()
			cfg.FailSeverity = tt.severity

			err := cfg.Validate()
			if tt.valid {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid fail_severity")
			}
		})
	}
}

func TestConfig_FindConfigFile_ExplicitPath(t *testing.T) {
	path := writeTestFile(t, "framework: soc2")
	result := findConfigFile(path)
	assert.Equal(t, path, result)
}

func TestConfig_FindConfigFile_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck // Best effort cleanup in tests

	result := findConfigFile("")
	assert.Equal(t, "", result)
}

func TestConfig_FindConfigFile_CWD(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck // Best effort cleanup in tests

	err = os.WriteFile(filepath.Join(tmpDir, ".sigcomply.yaml"), []byte("framework: soc2"), 0o600)
	require.NoError(t, err)

	result := findConfigFile("")
	assert.Equal(t, ".sigcomply.yaml", result)
}

func TestConfig_LoadWithConfigPath(t *testing.T) {
	path := writeTestFile(t, testFrameworkISO)

	os.Unsetenv("SIGCOMPLY_FRAMEWORK") //nolint:errcheck // Best effort cleanup in tests

	cfg, err := LoadWithConfigPath(path)
	require.NoError(t, err)
	assert.Equal(t, "iso27001", cfg.Framework)
	assert.Equal(t, path, cfg.ConfigFile)
}

func TestConfig_LoadFromFile_GitHubOrg(t *testing.T) {
	content := `
github:
  org: sigcomply
`
	path := writeTestFile(t, content)

	cfg := New()
	cfg.LoadFromFile(path)

	assert.Equal(t, "sigcomply", cfg.GitHub.Org)
}

func TestConfig_LoadFromFile_AWSRegions(t *testing.T) {
	content := `
aws:
  regions: [us-east-1, us-west-2]
`
	path := writeTestFile(t, content)

	cfg := New()
	cfg.LoadFromFile(path)

	assert.Equal(t, []string{"us-east-1", "us-west-2"}, cfg.AWS.Regions)
}

func TestConfig_LoadFromEnv_GitHubOrg(t *testing.T) {
	t.Setenv("SIGCOMPLY_GITHUB_ORG", "my-org")

	cfg := New()
	cfg.LoadFromEnv()

	assert.Equal(t, "my-org", cfg.GitHub.Org)
}

func TestConfig_LoadFromEnv_AWSRegion(t *testing.T) {
	t.Setenv("SIGCOMPLY_AWS_REGION", "eu-west-1")

	cfg := New()
	cfg.LoadFromEnv()

	assert.Equal(t, []string{"eu-west-1"}, cfg.AWS.Regions)
}

func TestConfig_Precedence_EnvOverridesFile_GitHubOrg(t *testing.T) {
	content := `
github:
  org: file-org
`
	path := writeTestFile(t, content)

	t.Setenv("SIGCOMPLY_GITHUB_ORG", "env-org")

	cfg := New()
	cfg.LoadFromFile(path)
	assert.Equal(t, "file-org", cfg.GitHub.Org)

	cfg.LoadFromEnv()
	assert.Equal(t, "env-org", cfg.GitHub.Org)
}

func TestConfig_Precedence_EnvOverridesFile_AWSRegion(t *testing.T) {
	content := `
aws:
  regions: [us-east-1, us-west-2]
`
	path := writeTestFile(t, content)

	t.Setenv("SIGCOMPLY_AWS_REGION", "ap-southeast-1")

	cfg := New()
	cfg.LoadFromFile(path)
	assert.Equal(t, []string{"us-east-1", "us-west-2"}, cfg.AWS.Regions)

	cfg.LoadFromEnv()
	assert.Equal(t, []string{"ap-southeast-1"}, cfg.AWS.Regions)
}

func TestConfig_LoadFromFile_Policies(t *testing.T) {
	content := `
framework: soc2
policies:
  - cc6_1_mfa
  - cc6_1_github_mfa
`
	path := writeTestFile(t, content)

	cfg := New()
	cfg.LoadFromFile(path)

	assert.Equal(t, []string{"cc6_1_mfa", "cc6_1_github_mfa"}, cfg.Policies)
}

func TestConfig_LoadFromFile_Controls(t *testing.T) {
	content := `
framework: soc2
controls:
  - CC6.1
  - CC7.1
`
	path := writeTestFile(t, content)

	cfg := New()
	cfg.LoadFromFile(path)

	assert.Equal(t, []string{"CC6.1", "CC7.1"}, cfg.Controls)
}

func TestConfig_LoadFromEnv_Policies(t *testing.T) {
	t.Setenv("SIGCOMPLY_POLICIES", "cc6_1_mfa, cc6_1_github_mfa")

	cfg := New()
	cfg.LoadFromEnv()

	assert.Equal(t, []string{"cc6_1_mfa", "cc6_1_github_mfa"}, cfg.Policies)
}

func TestConfig_LoadFromEnv_Controls(t *testing.T) {
	t.Setenv("SIGCOMPLY_CONTROLS", "CC6.1,CC7.1")

	cfg := New()
	cfg.LoadFromEnv()

	assert.Equal(t, []string{"CC6.1", "CC7.1"}, cfg.Controls)
}

func TestConfig_Precedence_EnvOverridesFile_Policies(t *testing.T) {
	content := `
policies:
  - cc6_1_mfa
`
	path := writeTestFile(t, content)

	t.Setenv("SIGCOMPLY_POLICIES", "cc7_1_logging")

	cfg := New()
	cfg.LoadFromFile(path)
	assert.Equal(t, []string{"cc6_1_mfa"}, cfg.Policies)

	cfg.LoadFromEnv()
	assert.Equal(t, []string{"cc7_1_logging"}, cfg.Policies)
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b , c ", []string{"a", "b", "c"}},
		{"a", []string{"a"}},
		{"", []string{}},
		{",,,", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitAndTrim(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_ManualEvidence_Defaults(t *testing.T) {
	cfg := New()

	assert.False(t, cfg.ManualEvidence.Enabled)
	assert.Nil(t, cfg.ManualEvidence.Default)
	assert.Empty(t, cfg.ManualEvidence.Frameworks)
}

func TestConfig_ManualEvidence_DefaultFromFile(t *testing.T) {
	content := `
manual_evidence:
  enabled: true
  default:
    backend: s3
    s3:
      bucket: shared-evidence
      region: us-east-1
      prefix: manual/
`
	path := writeTestFile(t, content)

	cfg := New()
	cfg.LoadFromFile(path)

	assert.True(t, cfg.ManualEvidence.Enabled)
	require.NotNil(t, cfg.ManualEvidence.Default)
	assert.Equal(t, "s3", cfg.ManualEvidence.Default.Backend)
	assert.Equal(t, "shared-evidence", cfg.ManualEvidence.Default.Bucket)
	assert.Equal(t, "us-east-1", cfg.ManualEvidence.Default.Region)
	assert.Equal(t, "manual/", cfg.ManualEvidence.Default.Prefix)
}

func TestConfig_ManualEvidence_PerFrameworkFromFile(t *testing.T) {
	content := `
manual_evidence:
  enabled: true
  frameworks:
    soc2:
      backend: s3
      s3:
        bucket: soc2-evidence
        region: us-east-1
    iso27001:
      backend: gcs
      gcs:
        bucket: iso27001-evidence
        prefix: manual/
    hipaa:
      backend: azure_blob
      azure_blob:
        account: hipaaev
        container: evidence
`
	path := writeTestFile(t, content)

	cfg := New()
	cfg.LoadFromFile(path)

	require.NotNil(t, cfg.ManualEvidence.Frameworks["soc2"])
	assert.Equal(t, "s3", cfg.ManualEvidence.Frameworks["soc2"].Backend)
	assert.Equal(t, "soc2-evidence", cfg.ManualEvidence.Frameworks["soc2"].Bucket)

	require.NotNil(t, cfg.ManualEvidence.Frameworks["iso27001"])
	assert.Equal(t, "gcs", cfg.ManualEvidence.Frameworks["iso27001"].Backend)
	assert.Equal(t, "iso27001-evidence", cfg.ManualEvidence.Frameworks["iso27001"].Bucket)
	assert.Equal(t, "manual/", cfg.ManualEvidence.Frameworks["iso27001"].Prefix)

	require.NotNil(t, cfg.ManualEvidence.Frameworks["hipaa"])
	assert.Equal(t, "azure_blob", cfg.ManualEvidence.Frameworks["hipaa"].Backend)
	assert.Equal(t, "hipaaev", cfg.ManualEvidence.Frameworks["hipaa"].Account)
	assert.Equal(t, "evidence", cfg.ManualEvidence.Frameworks["hipaa"].Container)
}

func TestConfig_ManualEvidence_For_PrefersFramework(t *testing.T) {
	cfg := &ManualEvidenceConfig{
		Enabled: true,
		Default: &StorageConfig{Backend: "s3", Bucket: "default-bucket"},
		Frameworks: map[string]*StorageConfig{
			"soc2": {Backend: "gcs", Bucket: "soc2-bucket"},
		},
	}

	soc2Cfg, err := cfg.For("soc2")
	require.NoError(t, err)
	assert.Equal(t, "gcs", soc2Cfg.Backend)
	assert.Equal(t, "soc2-bucket", soc2Cfg.Bucket)

	hipaaCfg, err := cfg.For("hipaa")
	require.NoError(t, err)
	assert.Equal(t, "s3", hipaaCfg.Backend, "frameworks without explicit config should fall back to Default")
	assert.Equal(t, "default-bucket", hipaaCfg.Bucket)
}

func TestConfig_ManualEvidence_For_ErrorsWhenNoSource(t *testing.T) {
	cfg := &ManualEvidenceConfig{Enabled: true}
	_, err := cfg.For("soc2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "soc2")
	assert.Contains(t, err.Error(), "no source configured")
}

func TestConfig_ManualEvidence_EnabledFromEnv(t *testing.T) {
	t.Setenv("SIGCOMPLY_MANUAL_EVIDENCE_ENABLED", "true")

	cfg := New()
	cfg.LoadFromEnv()

	assert.True(t, cfg.ManualEvidence.Enabled)
}

// writeTestFile creates a temporary YAML file and returns its path.
func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, ".sigcomply.yaml")
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)
	return path
}
