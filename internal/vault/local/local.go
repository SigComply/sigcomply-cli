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

// PutEnvelope serializes the envelope to JSON and writes it. Canonical
// JSON encoding (the form fed into the signer) is the signer's
// responsibility upstream — this layer is pure storage.
func (v *Vault) PutEnvelope(_ context.Context, key string, e *core.Envelope) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("local vault: marshal envelope: %w", err)
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

// GetBinary reads the file at key and returns its bytes. A missing
// file is reported as an error containing "not found"; callers can
// match against errors.Is(err, fs.ErrNotExist) for type-safe checks.
func (v *Vault) GetBinary(_ context.Context, key string) ([]byte, error) {
	path, err := v.resolve(key)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("local vault: not found: %s: %w", key, err)
		}
		return nil, fmt.Errorf("local vault: read %s: %w", key, err)
	}
	return data, nil
}

// List walks the filesystem under prefix and returns the keys it finds
// (relative to Root, with forward slashes). The walk follows the spec:
// prefixes are slash-terminated logical buckets; directories without
// any files are not reported.
func (v *Vault) List(_ context.Context, prefix string) ([]string, error) {
	root, err := v.resolve(prefix)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("local vault: stat %s: %w", prefix, err)
	}
	if !info.IsDir() {
		// Prefix points at a single file — list that one key.
		return []string{prefix}, nil
	}
	var keys []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(v.Root, path)
		if err != nil {
			return err
		}
		keys = append(keys, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("local vault: walk %s: %w", prefix, err)
	}
	return keys, nil
}

func (v *Vault) write(key string, data []byte) error {
	path, err := v.resolve(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("local vault: mkdir for %s: %w", key, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("local vault: write %s: %w", key, err)
	}
	return nil
}

// resolve joins key onto Root and rejects paths that escape the Root
// via "..", absolute paths, or symlink-shaped trickery. Vaults are
// trusted internal storage, but a buggy caller passing user input
// shouldn't be able to write outside the configured root.
func (v *Vault) resolve(key string) (string, error) {
	if v.Root == "" {
		return "", fmt.Errorf("local vault: not initialized (Root empty)")
	}
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("local vault: key %q must be relative, not absolute", key)
	}
	cleanedRoot := filepath.Clean(v.Root)
	joined := filepath.Join(cleanedRoot, filepath.FromSlash(key))
	cleaned := filepath.Clean(joined)
	if cleaned != cleanedRoot && !strings.HasPrefix(cleaned, cleanedRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("local vault: key %q escapes vault root", key)
	}
	return cleaned, nil
}

// Compile-time assertion that *Vault satisfies core.Vault.
var _ core.Vault = (*Vault)(nil)
