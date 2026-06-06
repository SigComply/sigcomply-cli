package vault_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
	_ "github.com/sigcomply/sigcomply-cli/internal/vault/builtin" // registers every in-tree backend via init()
)

func TestFromConfig_LocalSucceeds(t *testing.T) {
	v, err := vault.FromConfig(context.Background(), &spec.VaultConfig{
		Backend: "local",
		Config:  map[string]any{"path": t.TempDir()},
	})
	if err != nil {
		t.Fatalf("FromConfig(local): %v", err)
	}
	if v == nil {
		t.Fatal("FromConfig returned nil vault with nil error")
	}
}

// TestFromConfig_BackendRequiredFields verifies that per-backend
// required-field validation now lives in the backend factory (not a
// central switch in internal/spec): a backend with missing required keys
// errors clearly at FromConfig, naming the missing field. This is the
// registry-driven replacement for the old validateVault switch.
func TestFromConfig_BackendRequiredFields(t *testing.T) {
	cases := []struct {
		name    string
		cfg     spec.VaultConfig
		wantSub string
	}{
		{"s3 missing bucket", spec.VaultConfig{Backend: "s3", Config: map[string]any{"region": "us-east-1"}}, "bucket"},
		{"s3 missing region", spec.VaultConfig{Backend: "s3", Config: map[string]any{"bucket": "b"}}, "region"},
		{"gcs missing bucket", spec.VaultConfig{Backend: "gcs", Config: map[string]any{}}, "bucket"},
		{"azure missing container", spec.VaultConfig{Backend: "azure_blob", Config: map[string]any{"account": "a"}}, "container"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			_, err := vault.FromConfig(context.Background(), &cfg)
			if err == nil {
				t.Fatalf("FromConfig(%s): expected error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention missing field %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestFromConfig_UnknownBackendErrors(t *testing.T) {
	_, err := vault.FromConfig(context.Background(), &spec.VaultConfig{
		Backend: "tape_drive",
	})
	if err == nil {
		t.Fatal("expected error for unknown backend; got nil")
	}
	if !strings.Contains(err.Error(), "tape_drive") {
		t.Errorf("error %q does not name the offending backend", err.Error())
	}
}

func TestFromConfig_EmptyBackendErrors(t *testing.T) {
	_, err := vault.FromConfig(context.Background(), &spec.VaultConfig{})
	if err == nil {
		t.Fatal("expected error for empty backend; got nil")
	}
}

// TestRegistry_AllBuiltinsRegistered guards against silent regressions
// in the vault/builtin import list: if a backend forgets to register
// itself, or builtin forgets to blank-import it, the orchestrator will
// reject perfectly valid project configs at runtime. Catching it here
// turns that into a build-time failure.
func TestRegistry_AllBuiltinsRegistered(t *testing.T) {
	for _, id := range []string{"local", "s3", "gcs", "azure_blob"} {
		if _, ok := vault.Lookup(id); !ok {
			t.Errorf("vault backend %q not registered (check internal/vault/builtin and the backend's init())", id)
		}
	}
}

// TestRegistry_RegisterBackend_PanicsOnEmptyID verifies the programmer-
// error guard: an empty ID must panic immediately at process start so the
// misconfiguration is caught at init() time rather than silently at
// runtime when a vault.FromConfig call misses the backend.
func TestRegistry_RegisterBackend_PanicsOnEmptyID(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterBackend with empty ID: expected panic, recovered nil")
		}
	}()
	vault.RegisterBackend("", func(_ context.Context, _ *spec.VaultConfig) (core.Vault, error) {
		return nil, nil
	})
}

// TestRegistry_RegisterBackend_PanicsOnNilFactory verifies the guard for
// a nil factory — another programmer error that would cause a nil-pointer
// dereference in FromConfig.
func TestRegistry_RegisterBackend_PanicsOnNilFactory(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterBackend with nil factory: expected panic, recovered nil")
		}
	}()
	vault.RegisterBackend("__nil_factory_test__", nil)
}

// TestRegistry_RegisterBackend_PanicsOnDuplicate verifies that a second
// RegisterBackend call with the same ID panics. Duplicate registrations
// among in-tree backends are programming errors; the first registration
// wins in a real process so a duplicate would silently replace it.
func TestRegistry_RegisterBackend_PanicsOnDuplicate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterBackend duplicate ID: expected panic, recovered nil")
		}
	}()
	id := "__dup_test__"
	f := func(_ context.Context, _ *spec.VaultConfig) (core.Vault, error) { return nil, nil }
	vault.RegisterBackend(id, f)
	vault.RegisterBackend(id, f) // second call must panic
}
