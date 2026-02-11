//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"gopkg.in/yaml.v3"
)

// E2EConfig is the top-level configuration for E2E tests.
type E2EConfig struct {
	Version         string                       `yaml:"version"`
	Defaults        Defaults                     `yaml:"defaults"`
	Credentials     map[string]CredentialProfile `yaml:"credentials"`
	StorageProfiles map[string]StorageProfile    `yaml:"storage_profiles"`
	Signing         SigningConfig                `yaml:"signing"`
	Scenarios       []Scenario                   `yaml:"scenarios"`
}

// Defaults holds default values applied to all scenarios.
type Defaults struct {
	Timeout int `yaml:"timeout"`
}

// CredentialProfile defines a named set of credentials for a provider.
// Env var names are configurable so different profiles (positive, negative)
// can reference different env vars for the same provider type.
type CredentialProfile struct {
	Provider    string            `yaml:"provider"`
	Description string            `yaml:"description"`
	EnvVars     map[string]string `yaml:"env_vars"`
}

// StorageProfile defines a storage backend configuration.
// Sensitive values (bucket names) come from env vars; static config is inline.
type StorageProfile struct {
	Backend string            `yaml:"backend"`
	EnvVars map[string]string `yaml:"env_vars"`
	Config  map[string]string `yaml:"config"`
}

// SigningConfig holds signing-related configuration.
type SigningConfig struct {
	EnvVars       map[string]string `yaml:"env_vars"`
	DefaultSecret string            `yaml:"default_secret"`
}

// Scenario defines a single E2E test scenario.
type Scenario struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Enabled     bool              `yaml:"enabled"`
	Credentials string            `yaml:"credentials"` // references a credential profile name
	Framework   string            `yaml:"framework"`
	Storage     string            `yaml:"storage"` // references a storage profile name (optional)
	Assertions  ScenarioAssertion `yaml:"assertions"`
}

// ScenarioAssertion defines what to assert for this scenario.
//
// The pipeline phases (collect, evaluate, hash, sign) always run and are
// always verified. These fields control edge-case behavior and specific
// expected outcomes:
//
//   - CollectionErrorsExpected: true for negative/permission-denied tests
//   - ExpectedPolicyResults: assert specific pass/fail/skip per policy
//
// Storage phases only run when the scenario has a "storage" profile set.
type ScenarioAssertion struct {
	// CollectionErrorsExpected: if true, the test expects collection errors
	// (permission denied) and allows zero evidence. If false (default),
	// the test requires at least 1 evidence item.
	CollectionErrorsExpected bool `yaml:"collection_errors_expected"`

	// ExpectedPolicyResults maps policy IDs to expected status (pass, fail, skip).
	// Only listed policies are checked — unlisted policies can have any valid status.
	// Omit entirely to skip per-policy assertions.
	ExpectedPolicyResults map[string]string `yaml:"expected_policy_results"`
}

// ResolvedCredentials holds actual credential values resolved from environment variables.
type ResolvedCredentials struct {
	Provider string
	Values   map[string]string
}

// ResolvedStorage holds resolved storage configuration with env vars substituted.
type ResolvedStorage struct {
	Backend string
	Config  map[string]string
}

// LoadConfig reads and parses the E2E config YAML file.
// The config path is resolved relative to this source file.
func LoadConfig() (*E2EConfig, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("failed to determine config.go source path")
	}

	// Navigate from test/e2e/config.go -> ../../e2e/config.yaml
	configPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "e2e", "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	var cfg E2EConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// EnabledScenarios returns only enabled scenarios.
// If the E2E_SCENARIO env var is set, only that scenario is returned.
func (c *E2EConfig) EnabledScenarios() []Scenario {
	targetScenario := os.Getenv("E2E_SCENARIO")

	var result []Scenario
	for _, s := range c.Scenarios {
		if !s.Enabled {
			continue
		}
		if targetScenario != "" && s.Name != targetScenario {
			continue
		}
		result = append(result, s)
	}

	return result
}

// ResolveCredentials resolves a credential profile's env vars to actual values.
// Returns an error listing any missing env vars. The caller should t.Skip on error
// (missing credentials means the scenario can't run, not that something is broken).
func (c *E2EConfig) ResolveCredentials(profileName string) (*ResolvedCredentials, error) {
	profile, ok := c.Credentials[profileName]
	if !ok {
		return nil, fmt.Errorf("credential profile %q not found in config", profileName)
	}

	resolved := &ResolvedCredentials{
		Provider: profile.Provider,
		Values:   make(map[string]string),
	}

	var missing []string
	for key, envVar := range profile.EnvVars {
		val := os.Getenv(envVar)
		if val == "" {
			missing = append(missing, envVar)
			continue
		}
		resolved.Values[key] = val
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("missing env vars for credential profile %q: %v", profileName, missing)
	}

	return resolved, nil
}

// ResolveStorage resolves a storage profile's env vars and merges with static config.
// Env var values override static config if both define the same key.
func (c *E2EConfig) ResolveStorage(profileName string) (*ResolvedStorage, error) {
	profile, ok := c.StorageProfiles[profileName]
	if !ok {
		return nil, fmt.Errorf("storage profile %q not found in config", profileName)
	}

	resolved := &ResolvedStorage{
		Backend: profile.Backend,
		Config:  make(map[string]string),
	}

	// Copy static config values first
	for k, v := range profile.Config {
		resolved.Config[k] = v
	}

	// Resolve env vars (overrides static config if both exist for same key)
	var missing []string
	for key, envVar := range profile.EnvVars {
		val := os.Getenv(envVar)
		if val == "" {
			missing = append(missing, envVar)
			continue
		}
		resolved.Config[key] = val
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("missing env vars for storage profile %q: %v", profileName, missing)
	}

	return resolved, nil
}

// ResolveHMACSecret resolves the HMAC signing secret from env var or default.
func (c *E2EConfig) ResolveHMACSecret() []byte {
	if envVar, ok := c.Signing.EnvVars["hmac_secret"]; ok {
		if val := os.Getenv(envVar); val != "" {
			return []byte(val)
		}
	}
	if c.Signing.DefaultSecret != "" {
		return []byte(c.Signing.DefaultSecret)
	}
	return []byte("e2e-test-hmac-secret-default")
}
