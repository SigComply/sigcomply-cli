// Package telemetry provides error tracking and telemetry functionality.
package telemetry

import (
	"os"
	"time"

	"github.com/getsentry/sentry-go"
)

// Default Sentry DSN for SigComply CLI
const defaultSentryDSN = "https://a1b82bde95a2013a7b53753799dd0864@o4510676699250688.ingest.de.sentry.io/4510766822129744"

// Config holds telemetry configuration.
type Config struct {
	// DSN is the Sentry DSN. If empty, uses default.
	DSN string

	// Enabled controls whether telemetry is enabled.
	// Can be disabled via SIGCOMPLY_TELEMETRY_DISABLED=true
	Enabled bool

	// Environment is the deployment environment (development, staging, production).
	Environment string

	// Version is the CLI version.
	Version string

	// Debug enables debug mode for Sentry.
	Debug bool
}

// DefaultConfig returns the default telemetry configuration.
func DefaultConfig(version string) *Config {
	cfg := &Config{
		DSN:         defaultSentryDSN,
		Enabled:     true,
		Environment: "production",
		Version:     version,
		Debug:       false,
	}

	// Allow override via environment variables
	if dsn := os.Getenv("SIGCOMPLY_SENTRY_DSN"); dsn != "" {
		cfg.DSN = dsn
	}

	// Allow disabling telemetry
	if disabled := os.Getenv("SIGCOMPLY_TELEMETRY_DISABLED"); disabled == "true" || disabled == "1" {
		cfg.Enabled = false
	}

	// Detect environment
	if env := os.Getenv("SIGCOMPLY_ENVIRONMENT"); env != "" {
		cfg.Environment = env
	} else if os.Getenv("CI") != "" {
		cfg.Environment = "ci"
	}

	return cfg
}

// Init initializes Sentry with the given configuration.
// Returns a cleanup function that should be deferred.
func Init(cfg *Config) func() {
	if !cfg.Enabled || cfg.DSN == "" {
		return func() {}
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              cfg.DSN,
		Environment:      cfg.Environment,
		Release:          "sigcomply-cli@" + cfg.Version,
		Debug:            cfg.Debug,
		AttachStacktrace: true,
		// Sample rate for error events (1.0 = 100%)
		SampleRate: 1.0,
		// Don't send PII
		SendDefaultPII: false,
		// Set server name to empty to avoid sending hostname
		ServerName: "",
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			// Scrub any potentially sensitive data
			return scrubEvent(event)
		},
	})

	if err != nil {
		// Silently fail - telemetry should not break the CLI
		return func() {}
	}

	// Return cleanup function
	return func() {
		sentry.Flush(2 * time.Second)
	}
}

// CaptureException captures an exception and sends it to Sentry.
func CaptureException(err error) {
	sentry.CaptureException(err)
}

// CaptureMessage captures a message and sends it to Sentry.
func CaptureMessage(msg string) {
	sentry.CaptureMessage(msg)
}

// RecoverAndReport recovers from a panic and reports it to Sentry.
// Should be called with defer at the start of main goroutines.
func RecoverAndReport() {
	if r := recover(); r != nil {
		sentry.CurrentHub().Recover(r)
		sentry.Flush(2 * time.Second)
		// Re-panic after reporting
		panic(r)
	}
}

// SetUser sets user context for Sentry events.
// We only use anonymous identifiers, no PII.
func SetUser(id string) {
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetUser(sentry.User{ID: id})
	})
}

// SetTag sets a tag on the current scope.
func SetTag(key, value string) {
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag(key, value)
	})
}

// SetContext sets additional context for Sentry events.
func SetContext(key string, value map[string]interface{}) {
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetContext(key, value)
	})
}

// scrubEvent removes any potentially sensitive information from events.
func scrubEvent(event *sentry.Event) *sentry.Event {
	// Scrub environment variables that might contain secrets
	sensitiveEnvVars := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"GITHUB_TOKEN",
		"SIGCOMPLY_API_TOKEN",
		"SIGCOMPLY_SIGNING_KEY",
	}

	for _, envVar := range sensitiveEnvVars {
		if event.Contexts["os"] != nil {
			if env, ok := event.Contexts["os"]["env"].(map[string]string); ok {
				delete(env, envVar)
			}
		}
	}

	return event
}
