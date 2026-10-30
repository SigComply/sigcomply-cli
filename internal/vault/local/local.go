// Package local implements core.Vault on the local filesystem. The
// vault root is a directory tree the CLI writes per-run folders into.
// Suitable for development, single-host deployments, or any case where
// the vault and the CLI live on the same machine.
package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
)

// Vault is a filesystem-backed core.Vault. Every Put writes to
// filepath.Join(Root, key). Cleanup, encryption, and access control
// are the operator's responsibility.
type Vault struct {
	Root string
}

// New constructs a local Vault rooted at the given directory. The
// directory is created by Init if it does not already exist.
func New(root string) *Vault {
	return &Vault{Root: root}
}

// Init creates the vault root directory if it does not exist. Mode
// 0o755 matches Go's default for MkdirAll; operators wanting tighter
// permissions should pre-create the directory.
func (v *Vault) Init(_ context.Context) error {
	if v.Root == "" {
		return fmt.Errorf("local vault: Root must be non-empty")
	}
	if err := os.MkdirAll(v.Root, 0o750); err != nil {
		return fmt.Errorf("local vault: mkdir %s: %w", v.Root, err)
	}
	return nil
}

// PutEnvelope writes the envelope as canonical JSON. The on-disk
// bytes are byte-identical to the bytes fed into the signer, so a
// reader can either re-canonicalize on parse or check the file's
// SHA-256 against a recorded hash. The envelope must already be
// signed; PutEnvelope returns an error if not.
func (v *Vault) PutEnvelope(_ context.Context, key string, e *core.Envelope) error {
	body, err := sign.EncodeEnvelope(e)
	if err != nil {
		return fmt.Errorf("local vault: encode envelope: %w", err)
	}
	return v.write(key, body)
}

// PutJSON marshals body as JSON and writes it.
func (v *Vault) PutJSON(_ context.Context, key string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("local vault: marshal json for %s: %w", key, err)
	}
	return v.write(key, data)
}

// PutBinary writes the raw bytes. The metadata map is accepted for
// interface symmetry with object-store backends but is not persisted
// on the filesystem.
func (v *Vault) PutBinary(_ context.Context, key string, body []byte, _ map[string]string) error {
	return v.write(key, body)
}

// GetBinary reads the regular file at key and returns its bytes. A
// missing file is reported as an error containing "not found"; callers
// can match against errors.Is(err, fs.ErrNotExist) for type-safe checks.
// A symlink, directory or device at key is an error.
func (v *Vault) GetBinary(_ context.Context, key string) (_ []byte, err error) {
	name, err := v.resolve(key)
	if err != nil {
		return nil, err
	}
	root, err := v.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err := regularOrMissing(root, name, key); err != nil {
		return nil, err
	}
	data, err := root.ReadFile(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("local vault: not found: %s: %w", key, err)
		}
		return nil, fmt.Errorf("local vault: read %s: %w", key, err)
	}
	return data, nil
}

// List walks the filesystem under prefix and returns the keys of the
// regular files it finds (relative to Root, with forward slashes). The
// walk follows the spec: prefixes are slash-terminated logical buckets;
// directories without any files are not reported. Symlinks are neither
// followed nor reported.
func (v *Vault) List(_ context.Context, prefix string) (_ []string, err error) {
	name, err := v.resolve(prefix)
	if err != nil {
		return nil, err
	}
	root, err := v.openRoot()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("local vault: stat %s: %w", prefix, err)
	}
	if info.Mode().IsRegular() {
		// Prefix points at a single file — list that one key.
		return []string{prefix}, nil
	}
	if !info.IsDir() {
		return nil, nil
	}
	var keys []string
	err = fs.WalkDir(root.FS(), filepath.ToSlash(name), func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type().IsRegular() {
			keys = append(keys, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("local vault: walk %s: %w", prefix, err)
	}
	return keys, nil
}

func (v *Vault) write(key string, data []byte) (err error) {
	name, err := v.resolve(key)
	if err != nil {
		return err
	}
	root, err := v.openRoot()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err := root.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return fmt.Errorf("local vault: mkdir for %s: %w", key, err)
	}
	if err := regularOrMissing(root, name, key); err != nil {
		return err
	}
	if err := root.WriteFile(name, data, 0o600); err != nil {
		return fmt.Errorf("local vault: write %s: %w", key, err)
	}
	return nil
}

// openRoot opens the vault root with os.OpenRoot: every path below it
// is resolved inside the root, so a symlinked directory cannot lead a
// read or write outside it.
func (v *Vault) openRoot() (*os.Root, error) {
	root, err := os.OpenRoot(v.Root)
	if err != nil {
		return nil, fmt.Errorf("local vault: open root %s: %w", v.Root, err)
	}
	return root, nil
}

// regularOrMissing refuses a key whose final component is anything but
// a regular file (a symlink, even one inside the root, or a directory).
func regularOrMissing(root *os.Root, name, key string) error {
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("local vault: stat %s: %w", key, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("local vault: %s is not a regular file (symlinks are not followed)", key)
	}
	return nil
}

// resolve checks key and returns it as a path relative to Root ("." for
// the root itself). It rejects absolute keys and keys that escape the
// root via ".."; openRoot then keeps symlinks from escaping it.
func (v *Vault) resolve(key string) (string, error) {
	if v.Root == "" {
		return "", fmt.Errorf("local vault: not initialized (Root empty)")
	}
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("local vault: key %q must be relative, not absolute", key)
	}
	cleanedRoot := filepath.Clean(v.Root)
	cleaned := filepath.Clean(filepath.Join(cleanedRoot, filepath.FromSlash(key)))
	if cleaned != cleanedRoot && !strings.HasPrefix(cleaned, cleanedRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("local vault: key %q escapes vault root", key)
	}
	return filepath.Rel(cleanedRoot, cleaned)
}

// Compile-time assertion that *Vault satisfies core.Vault.
var _ core.Vault = (*Vault)(nil)
