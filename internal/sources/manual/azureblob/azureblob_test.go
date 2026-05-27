package azureblob_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/azureblob"
)

// unused import guard
var _ = strings.HasPrefix

type fakeFile struct {
	data       []byte
	uploadedAt time.Time
}

type fakeAzure struct {
	mu    sync.Mutex
	files map[string]fakeFile
	err   error
}

func (f *fakeAzure) Get(_ context.Context, key string) ([]byte, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, time.Time{}, f.err
	}
	o, ok := f.files[key]
	if !ok {
		return nil, time.Time{}, azureblob.ErrNotFound
	}
	return append([]byte(nil), o.data...), o.uploadedAt, nil
}

func (f *fakeAzure) List(_ context.Context, prefix string) ([]manual.FileInfo, error) {
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
	uploadedAt := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	fake := &fakeAzure{
		files: map[string]fakeFile{
			"manual/access_review/2026Q1/evidence.pdf": {
				data:       []byte("%PDF-1.4 hello"),
				uploadedAt: uploadedAt,
			},
		},
	}
	r := &azureblob.Reader{Client: fake, Account: "acct", Container: "cnt"}
	data, ts, err := r.Get(context.Background(), "manual/access_review/2026Q1/evidence.pdf")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "%PDF-1.4 hello" {
		t.Errorf("data = %q, want %q", data, "%PDF-1.4 hello")
	}
	if !ts.Equal(uploadedAt) {
		t.Errorf("uploadedAt = %v, want %v", ts, uploadedAt)
	}
}

func TestReader_Get_NotFound(t *testing.T) {
	fake := &fakeAzure{files: map[string]fakeFile{}}
	r := &azureblob.Reader{Client: fake, Account: "acct", Container: "cnt"}
	_, _, err := r.Get(context.Background(), "missing/path.pdf")
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if !errors.Is(err, manual.ErrNotFound) {
		t.Errorf("err = %v, want manual.ErrNotFound", err)
	}
}

func TestReader_Get_OtherErrorSurfaces(t *testing.T) {
	synthetic := errors.New("synthetic transport failure")
	fake := &fakeAzure{files: map[string]fakeFile{}, err: synthetic}
	r := &azureblob.Reader{Client: fake, Account: "acct", Container: "cnt"}
	_, _, err := r.Get(context.Background(), "any/key.pdf")
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if errors.Is(err, manual.ErrNotFound) {
		t.Errorf("err = %v, should NOT be coerced to manual.ErrNotFound", err)
	}
	if !errors.Is(err, synthetic) {
		t.Errorf("err = %v, want to wrap %v", err, synthetic)
	}
}

func TestRegister_Registered(t *testing.T) {
	if _, ok := manual.LookupReader("azure_blob"); !ok {
		t.Error("manual.LookupReader(\"azure_blob\") returned false; expected init() registration")
	}
}

func TestBuild_RejectsMissingAccount(t *testing.T) {
	f, ok := manual.LookupReader("azure_blob")
	if !ok {
		t.Fatal("azure_blob factory not registered")
	}
	_, _, _, _, err := f(map[string]any{"container": "c"})
	if err == nil {
		t.Fatal("build: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "account") {
		t.Errorf("err = %v, want it to mention \"account\"", err)
	}
}

func TestBuild_RejectsMissingContainer(t *testing.T) {
	f, ok := manual.LookupReader("azure_blob")
	if !ok {
		t.Fatal("azure_blob factory not registered")
	}
	_, _, _, _, err := f(map[string]any{"account": "a"})
	if err == nil {
		t.Fatal("build: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "container") {
		t.Errorf("err = %v, want it to mention \"container\"", err)
	}
}

func TestReader_List_ReturnsMatchingKeys(t *testing.T) {
	uploaded := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	fake := &fakeAzure{files: map[string]fakeFile{
		"manual/ev/2026-Q1/report.pdf": {data: []byte("x"), uploadedAt: uploaded},
		"manual/ev/2026-Q1/scan.jpg":   {data: []byte("y"), uploadedAt: uploaded},
		"manual/ev/2026-Q2/other.pdf":  {data: []byte("z"), uploadedAt: uploaded},
	}}
	r := &azureblob.Reader{Client: fake, Account: "acct", Container: "cnt"}
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
	r := &azureblob.Reader{Client: &fakeAzure{files: map[string]fakeFile{}}, Account: "acct", Container: "cnt"}
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
	fake := &fakeAzure{files: map[string]fakeFile{}, err: sentinel}
	r := &azureblob.Reader{Client: fake, Account: "acct", Container: "cnt"}
	_, err := r.List(context.Background(), "manual/ev/2026-Q1/")
	if err == nil {
		t.Fatal("List: expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("List: expected error to wrap sentinel, got %v", err)
	}
}
