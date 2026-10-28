package azureblob

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/storagetest"
)

const (
	sdkContainer = "sdk-evidence"
	sdkAccount   = "sdkaccount"
)

// sdkReader returns a Reader whose client is the production realAzure over
// a real azblob.Client, talking to a fake Blob Storage server.
func sdkReader(t *testing.T, pageSize int) (*Reader, *storagetest.AzureBlob) {
	t.Helper()
	srv := storagetest.NewAzureBlob(t, sdkContainer, pageSize)
	return &Reader{Client: &realAzure{svc: srv.Client(t), container: sdkContainer}, Account: sdkAccount, Container: sdkContainer}, srv
}

// A folder with more files than one list page holds must come back whole,
// each file with its upload time: the upload window is judged from it.
func TestRealAzure_ListFollowsEveryPage(t *testing.T) {
	r, srv := sdkReader(t, 2)
	base := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	for i := range 5 {
		srv.Put(fmt.Sprintf("manual/access_review/2026-Q3/page-%d.pdf", i), []byte("%PDF"), base.Add(time.Duration(i)*time.Hour))
	}
	srv.Put("manual/other/2026-Q3/x.pdf", []byte("%PDF"), base)

	items, err := r.List(context.Background(), "manual/access_review/2026-Q3/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 5 {
		t.Fatalf("List returned %d files; want 5: %+v", len(items), items)
	}
	for i, it := range items {
		want := fmt.Sprintf("manual/access_review/2026-Q3/page-%d.pdf", i)
		if it.Key != want || !it.UploadedAt.Equal(base.Add(time.Duration(i)*time.Hour)) {
			t.Errorf("item %d = %+v; want %s uploaded %s", i, it, want, base.Add(time.Duration(i)*time.Hour))
		}
	}
	if tokens := srv.PageTokens(); len(tokens) != 3 {
		t.Errorf("list requests = %d (markers %q); want 3", len(tokens), tokens)
	}
}

func TestRealAzure_GetReturnsBodyAndUploadTime(t *testing.T) {
	r, srv := sdkReader(t, 10)
	uploaded := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	srv.Put("manual/policy/2026/policy.pdf", []byte("%PDF-1.7 body"), uploaded)

	data, at, err := r.Get(context.Background(), "manual/policy/2026/policy.pdf")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "%PDF-1.7 body" || !at.Equal(uploaded) {
		t.Errorf("Get = %q at %s; want the stored body at %s", data, at, uploaded)
	}
}

func TestRealAzure_MissingFileIsErrNotFound(t *testing.T) {
	r, _ := sdkReader(t, 10)
	_, _, err := r.Get(context.Background(), "manual/policy/2026/missing.pdf")
	if !errors.Is(err, manual.ErrNotFound) {
		t.Errorf("err = %v; want manual.ErrNotFound", err)
	}
}
