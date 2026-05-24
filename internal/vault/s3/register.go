package s3

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

func init() {
	vault.RegisterBackend("s3", build)
}

func build(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
	v, err := New(ctx, Options{
		Bucket:         cfg.Bucket,
		Region:         cfg.Region,
		Prefix:         cfg.Prefix,
		Endpoint:       cfg.Endpoint,
		ForcePathStyle: cfg.ForcePathStyle,
	})
	if err != nil {
		return nil, err
	}
	if err := v.Init(ctx); err != nil {
		return nil, err
	}
	return v, nil
}
