package gcs_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/storage"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	gcsreader "github.com/sigcomply/sigcomply-cli/internal/sources/manual/gcs"
)

// unused import guard (strings is used in List test below)
var _ = strings.HasPrefix

type fakeFile struct {
	data       []byte
	uploadedAt time.Time
}

type fakeGCS struct {
	mu    sync.Mutex
	files map[string]fakeFile
	// err, when set, is returned by Get instead of looking up a file.
	// Used to exercise the non-NotFound error path.
	err error
}

func newFakeGCS() *fakeGCS {
	return &fakeGCS{files: map[string]fakeFile{}}
}

func (f *fakeGCS) Get(_ context.Context, key string) ([]byte, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, time.Time{}, f.err
	}
	o, ok := f.files[key]
	if !ok {
		return nil, time.Time{}, storage.ErrObjectNotExist
	}
	return append([]byte(nil), o.data...), o.uploadedAt, nil
}

func (f *fakeGCS) List(_ context.Context, prefix string) ([]manual.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var items []manual.FileInfo
	for key, ff := range f.files {
		if strings.HasPrefix(key, prefix) {
			items = append(items, manual.FileInfo{Key: key, UploadedAt: ff.uploadedAt})
		}
	}
	return items, nil
}

func TestReader_Get_Success(t *testing.T) {
	want := []byte("%PDF-1.7 fake pdf bytes /Page")
	wantTime := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fake := newFakeGCS()
	fake.files["manual/access_review/2026Q1/evidence.pdf"] = fakeFile{
		data:       want,
		uploadedAt: wantTime,
	}
	r := &gcsreader.Reader{Client: fake, Bucket: "test-bucket"}

	got, gotTime, err := r.Get(context.Background(), "manual/access_review/2026Q1/evidence.pdf")
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Get data: got %q, want %q", got, want)
	}
	if !gotTime.Equal(wantTime) {
		t.Errorf("Get time: got %v, want %v", gotTime, wantTime)
	}
}

func TestReader_Get_NotFound(t *testing.T) {
	fake := newFakeGCS()
	r := &gcsreader.Reader{Client: fake, Bucket: "test-bucket"}

	_, _, err := r.Get(context.Background(), "manual/missing/2026Q1/evidence.pdf")
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if !errors.Is(err, manual.ErrNotFound) {
		t.Errorf("Get: expected error to wrap manual.ErrNotFound, got %v", err)
	}
}

func TestReader_Get_OtherErrorSurfaces(t *testing.T) {
	sentinel := errors.New("synthetic gcs transport failure")
	fake := newFakeGCS()
	fake.err = sentinel
	r := &gcsreader.Reader{Client: fake, Bucket: "test-bucket"}

	_, _, err := r.Get(context.Background(), "manual/whatever/2026Q1/evidence.pdf")
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if errors.Is(err, manual.ErrNotFound) {
		t.Errorf("Get: synthetic error must NOT be coerced to manual.ErrNotFound, got %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Get: expected error to wrap synthetic sentinel, got %v", err)
	}
}

func TestRegister_Registered(t *testing.T) {
	if _, ok := manual.LookupReader("gcs"); !ok {
		t.Fatalf("manual.LookupReader(%q) = false, want true; registered IDs: %v", "gcs", manual.ReaderIDs())
	}
}

func TestBuild_RejectsMissingBucket(t *testing.T) {
	factory, ok := manual.LookupReader("gcs")
	if !ok {
		t.Fatal("gcs reader factory not registered")
	}
	_, _, _, _, err := factory(map[string]any{})
	if err == nil {
		t.Fatal("build with empty config: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "bucket") {
		t.Errorf("build error should mention \"bucket\", got: %v", err)
	}
}

func TestReader_List_ReturnsMatchingKeys(t *testing.T) {
	uploaded := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	fake := newFakeGCS()
	fake.files["manual/ev/2026-Q1/report.pdf"] = fakeFile{data: []byte("x"), uploadedAt: uploaded}
	fake.files["manual/ev/2026-Q1/scan.jpg"] = fakeFile{data: []byte("y"), uploadedAt: uploaded}
	fake.files["manual/ev/2026-Q2/other.pdf"] = fakeFile{data: []byte("z"), uploadedAt: uploaded}

	r := &gcsreader.Reader{Client: fake, Bucket: "test-bucket"}
	items, err := r.List(context.Background(), "manual/ev/2026-Q1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("List: got %d items, want 2; items: %v", len(items), items)
	}
	for _, item := range items {
		if !strings.HasPrefix(item.Key, "manual/ev/2026-Q1/") {
			t.Errorf("List: unexpected key %q for prefix \"manual/ev/2026-Q1/\"", item.Key)
		}
	}
}

func TestReader_List_Empty(t *testing.T) {
	r := &gcsreader.Reader{Client: newFakeGCS(), Bucket: "test-bucket"}
	items, err := r.List(context.Background(), "manual/ev/2026-Q1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("List: got %d items, want 0", len(items))
	}
}

func TestReader_List_ErrorSurfaces(t *testing.T) {
	sentinel := errors.New("synthetic list error")
	fake := newFakeGCS()
	fake.err = sentinel
	r := &gcsreader.Reader{Client: fake, Bucket: "test-bucket"}
	_, err := r.List(context.Background(), "manual/ev/2026-Q1/")
	if err == nil {
		t.Fatal("List: expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("List: expected error to wrap sentinel, got %v", err)
	}
}
