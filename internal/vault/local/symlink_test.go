package local_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
)

// symlinkFixture makes a vault root holding a symlinked file and a
// symlinked directory, both pointing at a secret outside the root.
func symlinkFixture(t *testing.T) (root, outside string) {
	t.Helper()
	root = t.TempDir()
	outside = t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("TOKEN"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "state", "soc2"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "state", "soc2", "link.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	return root, outside
}

// The vault is a directory an attacker with repository write access may
// shape (a checked-in .sigcomply/vault, a cache restored in CI). A
// symlink must not let a read return a file outside the root, nor a
// write land outside it.
func TestLocalVault_RefusesSymlinks(t *testing.T) {
	root, outside := symlinkFixture(t)
	v := local.New(root)
	ctx := context.Background()
	if data, err := v.GetBinary(ctx, "state/soc2/link.json"); err == nil {
		t.Errorf("GetBinary through a symlinked file = %q; want an error", data)
	}
	if data, err := v.GetBinary(ctx, "escape/secret"); err == nil {
		t.Errorf("GetBinary through a symlinked directory = %q; want an error", data)
	}
	if err := v.PutBinary(ctx, "escape/planted", []byte("x"), nil); err == nil {
		t.Error("PutBinary through a symlinked directory succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "planted")); err == nil {
		t.Error("a file was written outside the vault root")
	}
	if err := v.PutBinary(ctx, "state/soc2/link.json", []byte("x"), nil); err == nil {
		t.Error("PutBinary over a symlinked file succeeded")
	}
	if got, err := os.ReadFile(filepath.Join(outside, "secret")); err != nil || string(got) != "TOKEN" { //nolint:gosec // test temp dir
		t.Errorf("the symlink target was overwritten: %q, %v", got, err)
	}
	keys, err := v.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == "state/soc2/link.json" || filepath.Dir(k) == "escape" {
			t.Errorf("List reported %q, which is a symlink", k)
		}
	}
}
