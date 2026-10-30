package s3

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/endpoint"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

func init() {
	vault.RegisterBackend("s3", build)
	vault.RegisterBackendKeys("s3", "bucket", "region", "prefix", "endpoint", "force_path_style")
}

func build(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
	if cfg.Str("bucket") == "" {
		return nil, fmt.Errorf("vault: backend %q requires %q", "s3", "bucket")
	}
	if cfg.Str("region") == "" {
		return nil, fmt.Errorf("vault: backend %q requires %q", "s3", "region")
	}
	pathStyle, err := forcePathStyle(cfg)
	if err != nil {
		return nil, err
	}
	// The endpoint receives SigV4-signed requests that carry the session
	// token; same https rule as every other credentialed endpoint.
	if ep := cfg.Str("endpoint"); ep != "" {
		if err := endpoint.ValidateHTTPS(`vault s3: "endpoint"`, ep); err != nil {
			return nil, err
		}
	}
	v, err := New(ctx, Options{
		Bucket:         cfg.Str("bucket"),
		Region:         cfg.Str("region"),
		Prefix:         cfg.Str("prefix"),
		Endpoint:       cfg.Str("endpoint"),
		ForcePathStyle: pathStyle,
	})
	if err != nil {
		return nil, err
	}
	if err := v.Init(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

// forcePathStyle accepts a YAML bool or the strings "true"/"false". A quoted
// value used to read as false with no warning; anything else is an error.
func forcePathStyle(cfg *spec.VaultConfig) (bool, error) {
	switch v := cfg.Config["force_path_style"].(type) {
	case nil:
		return false, nil
	case bool:
		return v, nil
	case string:
		switch v {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("vault s3: %q must be true or false, got %v", "force_path_style", cfg.Config["force_path_style"])
}
