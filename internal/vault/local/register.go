package local

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

func init() {
	vault.RegisterBackend("local", build)
}

func build(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
	v := New(cfg.Path)
	if err := v.Init(ctx); err != nil {
		return nil, err
	}
	return v, nil
}
