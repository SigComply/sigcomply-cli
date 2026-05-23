package vault_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

func TestFromConfig_LocalSucceeds(t *testing.T) {
	v, err := vault.FromConfig(context.Background(), &spec.VaultConfig{
		Backend: "local",
		Path:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("FromConfig(local): %v", err)
	}
	if v == nil {
		t.Fatal("FromConfig returned nil vault with nil error")
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
