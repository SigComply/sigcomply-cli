package manual

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"
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
	// Every key any compiled-in reader backend reads (local: path;
	// s3: region, endpoint, force_path_style; azure_blob: account,
	// container). An unregistered key draws an "ignored" warning from
	// the config loader, which would be false for these.
	sources.RegisterFactory(SourceID, build, "backend", "bucket", "prefix", "path",
		"region", "endpoint", "force_path_style", "account", "container")
	// A boolean: the planner must not advise quoting it.
	sources.RegisterTypedConfigKeys(SourceID, "force_path_style")
	RegisterReader("local", buildLocalReader)
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

// ReaderFactory builds a Reader from the raw config map for the
// manual.pdf source. Each backend package registers its factory via
// init(); the manual.pdf plugin dispatches generically. Third-party
// backends (SFTP, MinIO, on-prem NFS, custom object stores) follow the
// same pattern from a project-local plugin compiled in by
// `sigcomply build` (M16) — no edits to internal/sources/manual
// required. See docs/architecture/00-three-plugin-axes.md §Axis A.
//
// The factory extracts backend-specific fields from raw and returns
// the Reader plus the (scheme, bucket, prefix) triple used to build
// the URI in emitted evidence records.
type ReaderFactory func(raw map[string]any) (reader Reader, scheme, bucket, prefix string, err error)

var (
	readerMu        sync.RWMutex
	readerFactories = map[string]ReaderFactory{}
)

// RegisterReader adds a backend factory under id. Intended for init()
// inside the backend's package. Duplicate IDs panic at process start —
// duplicates among in-tree backends are a programming error, and a
// project-local backend claiming a reserved ID is a misconfiguration
// the build should not let through.
func RegisterReader(id string, f ReaderFactory) {
	if id == "" {
		panic("manual: RegisterReader: empty ID")
	}
	if f == nil {
		panic("manual: RegisterReader: nil factory for " + id)
	}
	readerMu.Lock()
	defer readerMu.Unlock()
	if _, dup := readerFactories[id]; dup {
		panic("manual: duplicate reader registration for " + id)
	}
	readerFactories[id] = f
}

// LookupReader returns the factory registered under id, or (nil, false).
func LookupReader(id string) (ReaderFactory, bool) {
	readerMu.RLock()
	defer readerMu.RUnlock()
	f, ok := readerFactories[id]
	return f, ok
}

// ReaderIDs returns every registered reader backend ID in sorted
// order. Used to build helpful error messages when project config
// names an unknown backend.
func ReaderIDs() []string {
	readerMu.RLock()
	defer readerMu.RUnlock()
	out := make([]string, 0, len(readerFactories))
	for id := range readerFactories {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func buildReader(raw map[string]any) (reader Reader, scheme, bucket, prefix string, err error) {
	backend := sources.StringOpt(raw, "backend")
	if backend == "" {
		backend = "local"
	}
	f, ok := LookupReader(backend)
	if !ok {
		return nil, "", "", "", fmt.Errorf("manual.pdf backend %q not registered (compiled-in: %v; "+
			"third-party backends are compiled in via `sigcomply build`)", backend, ReaderIDs())
	}
	return f(raw)
}

func buildLocalReader(raw map[string]any) (reader Reader, scheme, bucket, prefix string, err error) {
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
}

// localReader satisfies Reader against a local directory tree. Lives
// here (rather than cmd/sigcomply) so the manual package owns its
// in-tree backend adapters; cloud backends (S3, GCS, Azure Blob) land
// as subpackages alongside the post-M6 plugin-set work, each calling
// RegisterReader from its own init().
type localReader struct {
	root string
}

// Get reads one regular file inside the root. The root is opened with
// os.OpenRoot, so no symlink can lead outside it, and a key whose final
// component is a symlink, device or directory is refused: a checked-in
// evidence folder could otherwise point a "PDF" at any file on the CI
// runner.
func (r *localReader) Get(_ context.Context, uri string) (_ []byte, _ time.Time, err error) {
	root, err := os.OpenRoot(r.root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, time.Time{}, ErrNotFound
		}
		return nil, time.Time{}, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	name := filepath.FromSlash(uri)
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, time.Time{}, ErrNotFound
		}
		return nil, time.Time{}, err
	}
	if !info.Mode().IsRegular() {
		return nil, time.Time{}, fmt.Errorf("manual.pdf.local: %s is not a regular file (symlinks are not followed)", uri)
	}
	if info.Size() > MaxFileBytes {
		return nil, time.Time{}, &FileTooLargeError{Key: uri, Limit: MaxFileBytes}
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	data, err := ReadAllLimited(f, uri, MaxFileBytes)
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, info.ModTime().UTC(), nil
}

// List returns the regular files directly in the prefix folder.
// Symlinks (to files or folders) are left out, like subfolders.
func (r *localReader) List(_ context.Context, prefix string) (_ []FileInfo, err error) {
	root, err := os.OpenRoot(r.root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	dir := path.Clean("./" + prefix)
	if info, err := root.Lstat(filepath.FromSlash(dir)); err != nil || !info.IsDir() {
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, nil // missing, or a symlink / file where a folder should be
	}
	entries, err := fs.ReadDir(root.FS(), dir)
	if err != nil {
		return nil, err
	}
	items := make([]FileInfo, 0, len(entries))
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		items = append(items, FileInfo{
			Key:        prefix + e.Name(),
			UploadedAt: info.ModTime().UTC(),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	return items, nil
}
