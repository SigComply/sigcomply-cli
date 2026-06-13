package azureblob

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

func init() {
	vault.RegisterBackend("azure_blob", build)
}

func build(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
	if cfg.Str("account") == "" || cfg.Str("container") == "" {
		return nil, fmt.Errorf("vault: backend %q requires %q and %q", "azure_blob", "account", "container")
	}
	v, err := New(ctx, Options{
		Account:   cfg.Str("account"),
		Container: cfg.Str("container"),
		Prefix:    cfg.Str("prefix"),
	})
	if err != nil {
		return nil, err
	}
	if err := v.Init(ctx); err != nil {
		return nil, err
	}
	return v, nil
}
