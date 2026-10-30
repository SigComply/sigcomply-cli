package manual

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// zeros is an endless reader: a backend that never stops sending.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestReadAllLimited(t *testing.T) {
	got, err := ReadAllLimited(bytes.NewReader(make([]byte, 10)), "k", 10)
	if err != nil || len(got) != 10 {
		t.Fatalf("at the limit: len=%d err=%v; want 10, nil", len(got), err)
	}
	_, err = ReadAllLimited(bytes.NewReader(make([]byte, 11)), "k", 10)
	var tooLarge *FileTooLargeError
	if !errors.As(err, &tooLarge) || tooLarge.Key != "k" || tooLarge.Limit != 10 {
		t.Fatalf("over the limit: err=%v; want *FileTooLargeError{Key: k, Limit: 10}", err)
	}
	// An endless body stops at the limit instead of exhausting memory.
	if _, err := ReadAllLimited(io.Reader(zeros{}), "k", 1<<20); !errors.As(err, &tooLarge) {
		t.Fatalf("endless body: err=%v; want *FileTooLargeError", err)
	}
}

// A local file larger than MaxFileBytes is refused from its size alone,
// without reading it into memory.
func TestLocalReader_RefusesOversizedFile(t *testing.T) {
	root := t.TempDir()
	key := "manual/ev/2026-Q1/huge.pdf"
	full := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(full) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxFileBytes + 1); err != nil { // sparse: no disk cost
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r := &localReader{root: root}
	_, _, err = r.Get(context.Background(), key)
	var tooLarge *FileTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("Get(oversized) err = %v; want *FileTooLargeError", err)
	}
}

// An oversized file fails its policy with an actionable message; it is
// not a transport error that turns the policy into status=error.
func TestCollect_FileTooLargeIsAValidationFailure(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := New(Options{
		Reader: &errOnGetReader{
			listItems: []FileInfo{{Key: testEvidencePathQ1, UploadedAt: uploadedAt}},
			getErr:    &FileTooLargeError{Key: testEvidencePathQ1, Limit: MaxFileBytes},
		},
		Bucket:  testBucket,
		Prefix:  defaultPrefix,
		Scheme:  "s3",
		Catalog: map[string]CatalogEntry{testCatalogID: {EvidenceID: testCatalogID}},
	})
	records, err := p.Collect(context.Background(), baseReq(testPeriodID, nil))
	if err != nil {
		t.Fatalf("Collect: %v; want a record with a validation failure", err)
	}
	m := unmarshalManifest(t, records)
	if m.FileValid {
		t.Error("FileValid = true; want false")
	}
	found := false
	for _, f := range m.ValidationFailures {
		if strings.HasPrefix(f, "file_too_large: ") && strings.Contains(f, "evidence.pdf") {
			found = true
		}
	}
	if !found {
		t.Errorf("ValidationFailures = %v; want a file_too_large entry naming evidence.pdf", m.ValidationFailures)
	}
}

// TestManualReadersCapReads is the class guard for unbounded reads of
// uploaded evidence: no manual-evidence backend may read a whole body or
// file without the MaxFileBytes cap. New backends inherit the rule.
func TestManualReadersCapReads(t *testing.T) {
	banned := regexp.MustCompile(`\bio\.ReadAll\(|\bos\.ReadFile\(|\bioutil\.ReadAll\(`)
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) //nolint:gosec // walking this package's own sources
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(src), "\n") {
			if banned.MatchString(line) && !strings.Contains(line, "io.LimitReader(") {
				t.Errorf("%s:%d reads evidence without a size cap; use manual.ReadAllLimited", path, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A checked-in evidence folder can hold a symlink to any file on the CI
// runner (credentials, /proc/self/environ). The local reader must read
// regular files inside its root only.
func TestLocalReader_RefusesSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.pdf"), []byte("%PDF-TOKEN"), 0o600); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "manual", "ev", "2026-Q1")
	if err := os.MkdirAll(folder, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.pdf"), filepath.Join(folder, "linked.pdf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "manual", "escape")); err != nil {
		t.Fatal(err)
	}
	r := &localReader{root: root}
	ctx := context.Background()
	if data, _, err := r.Get(ctx, "manual/ev/2026-Q1/linked.pdf"); err == nil {
		t.Errorf("Get(symlinked file) = %q; want an error", data)
	}
	if data, _, err := r.Get(ctx, "manual/escape/secret.pdf"); err == nil {
		t.Errorf("Get(through symlinked dir) = %q; want an error", data)
	}
	items, err := r.List(ctx, "manual/ev/2026-Q1/")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("List = %v; want the symlink left out", items)
	}
	if items, err := r.List(ctx, "manual/escape/"); err != nil || len(items) != 0 {
		t.Errorf("List(symlinked dir) = %v, %v; want nothing", items, err)
	}
}
