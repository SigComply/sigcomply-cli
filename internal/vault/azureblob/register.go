package azureblob

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

func init() {
	vault.RegisterBackend("azure_blob", build)
}

func build(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
	v, err := New(ctx, Options{
		Account:   cfg.Account,
		Container: cfg.Container,
		Prefix:    cfg.Prefix,
	})
	if err != nil {
		return nil, err
	}
	if err := v.Init(ctx); err != nil {
		return nil, err
	}
	return v, nil
}
