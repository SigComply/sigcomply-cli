package gcs

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

func init() {
	vault.RegisterBackend("gcs", build)
}

func build(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
	if cfg.Str("bucket") == "" {
		return nil, fmt.Errorf("vault: backend %q requires %q", "gcs", "bucket")
	}
	v, err := New(ctx, Options{
		Bucket: cfg.Str("bucket"),
		Prefix: cfg.Str("prefix"),
	})
	if err != nil {
		return nil, err
	}
	if err := v.Init(ctx); err != nil {
		return nil, err
	}
	return v, nil
}
