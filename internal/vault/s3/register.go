package s3

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

func init() {
	vault.RegisterBackend("s3", build)
}

func build(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
	if cfg.Str("bucket") == "" {
		return nil, fmt.Errorf("vault: backend %q requires %q", "s3", "bucket")
	}
	if cfg.Str("region") == "" {
		return nil, fmt.Errorf("vault: backend %q requires %q", "s3", "region")
	}
	v, err := New(ctx, Options{
		Bucket:         cfg.Str("bucket"),
		Region:         cfg.Str("region"),
		Prefix:         cfg.Str("prefix"),
		Endpoint:       cfg.Str("endpoint"),
		ForcePathStyle: cfg.Bool("force_path_style"),
	})
	if err != nil {
		return nil, err
	}
	if err := v.Init(ctx); err != nil {
		return nil, err
	}
	return v, nil
}
