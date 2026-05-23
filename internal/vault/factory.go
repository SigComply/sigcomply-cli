package vault

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault/azureblob"
	"github.com/sigcomply/sigcomply-cli/internal/vault/gcs"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
	"github.com/sigcomply/sigcomply-cli/internal/vault/s3"
)

// FromConfig constructs the right backend for the given project-config
// vault section. The returned Vault is already Init'd and ready for
// Put/Get/List. The factory layer is L7's seam to L8 (Orchestrator):
// every other layer takes a core.Vault and doesn't care which backend
// is behind it.
func FromConfig(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
	switch cfg.Backend {
	case "local":
		v := local.New(cfg.Path)
		if err := v.Init(ctx); err != nil {
			return nil, err
		}
		return v, nil
	case "s3":
		v, err := s3.New(ctx, s3.Options{
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
	case "gcs":
		v, err := gcs.New(ctx, gcs.Options{
			Bucket: cfg.Bucket,
			Prefix: cfg.Prefix,
		})
		if err != nil {
			return nil, err
		}
		if err := v.Init(ctx); err != nil {
			return nil, err
		}
		return v, nil
	case "azure_blob":
		v, err := azureblob.New(ctx, azureblob.Options{
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
	case "":
		return nil, fmt.Errorf("vault: backend not set in config")
	default:
		return nil, fmt.Errorf("vault: unsupported backend %q (want local|s3|gcs|azure_blob)", cfg.Backend)
	}
}
