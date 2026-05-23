package local_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
	"github.com/sigcomply/sigcomply-cli/internal/vault/vaulttest"
)

func TestLocalVault_Contract(t *testing.T) {
	vaulttest.RunContractSuite(t, func(t *testing.T) core.Vault {
		t.Helper()
		v := local.New(t.TempDir())
		if err := v.Init(context.Background()); err != nil {
			t.Fatalf("Init: %v", err)
		}
		return v
	})
}

func TestLocalVault_RejectsEscapingKey(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	bad := []string{
		"../escape.txt",
		"foo/../../escape.txt",
		"/absolute.txt",
	}
	for _, k := range bad {
		if err := v.PutBinary(context.Background(), k, []byte("x"), nil); err == nil {
			t.Errorf("PutBinary(%q) = nil; expected escape error", k)
		}
	}
}

func TestLocalVault_InitRejectsEmptyRoot(t *testing.T) {
	v := local.New("")
	if err := v.Init(context.Background()); err == nil {
		t.Error("Init on empty Root returned nil error")
	}
}

func TestLocalVault_ListOnMissingPrefix(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	keys, err := v.List(context.Background(), "no-such-dir/")
	if err != nil {
		t.Fatalf("List on missing prefix returned error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("List on missing prefix returned %v; want empty", keys)
	}
}

func TestLocalVault_ListOnSingleFile(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := v.PutBinary(context.Background(), "solo.bin", []byte("x"), nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	keys, err := v.List(context.Background(), "solo.bin")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || !strings.HasSuffix(keys[0], "solo.bin") {
		t.Errorf("List(solo.bin) = %v; want [solo.bin]", keys)
	}
}
