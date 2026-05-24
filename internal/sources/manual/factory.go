package manual

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// FrameworkCatalogKey is the key under which the orchestrator passes
// the active framework's manual catalog through sources.Env.
// Documented here so framework registration and the plugin agree on
// one place to look.
const FrameworkCatalogKey = "manual_catalog"

// defaultPrefix and localScheme are reused across construction and
// tests; extracted to avoid string-literal repetition the linter
// flags.
const (
	defaultPrefix = "manual/"
	localScheme   = "file"
)

func init() {
	sources.RegisterFactory(SourceID, build)
}

func build(_ context.Context, env sources.Env) (core.SourcePlugin, error) {
	reader, scheme, bucket, prefix, err := buildReader(env.Config)
	if err != nil {
		return nil, err
	}
	catalog, _ := env.FrameworkExtras[FrameworkCatalogKey].(map[string]CatalogEntry) //nolint:errcheck // safe-cast; nil catalog is a valid degraded mode
	return New(Options{
		Reader:  reader,
		Bucket:  bucket,
		Prefix:  prefix,
		Scheme:  scheme,
		Catalog: catalog,
	}), nil
}

func buildReader(raw map[string]any) (reader Reader, scheme, bucket, prefix string, err error) {
	backend := sources.StringOpt(raw, "backend")
	if backend == "" {
		backend = "local"
	}
	switch backend {
	case "local":
		root := sources.StringOpt(raw, "path")
		if root == "" {
			return nil, "", "", "", fmt.Errorf("manual.pdf.local: \"path\" required")
		}
		bucket = sources.StringOpt(raw, "bucket")
		if bucket == "" {
			bucket = root
		}
		prefix = sources.StringOpt(raw, "prefix")
		if prefix == "" {
			prefix = defaultPrefix
		}
		return &localReader{root: root}, localScheme, bucket, prefix, nil
	default:
		// Cloud-backed manual.pdf readers (s3, gcs, azure_blob) land
		// alongside the post-M6 plugin-set work; see
		// docs/architecture/09-implementation-roadmap.md.
		return nil, "", "", "", fmt.Errorf("manual.pdf backend %q not supported in v1-alpha (use \"local\")", backend)
	}
}

// localReader satisfies Reader against a local directory tree. Lives
// here (rather than cmd/sigcomply) so the manual package owns its
// backend adapters and the factory can stay generic.
type localReader struct {
	root string
}

func (r *localReader) Get(_ context.Context, uri string) ([]byte, time.Time, error) {
	full := strings.TrimRight(r.root, "/") + "/" + uri
	info, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, time.Time{}, ErrNotFound
		}
		return nil, time.Time{}, err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, info.ModTime().UTC(), nil
}
