package s3_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	manuals3 "github.com/sigcomply/sigcomply-cli/internal/sources/manual/s3"
	"github.com/sigcomply/sigcomply-cli/internal/storagetest"
)

// The fake S3 tests above stand in for the SDK. These run the real
// s3.Client against a fake endpoint, so request building, XML decoding and
// the not-found mapping are the production code paths.

// A folder with more files than one ListObjectsV2 page holds must come
// back whole: the reader follows NextContinuationToken until IsTruncated
// is false.
func TestReader_RealSDK_ListFollowsEveryPage(t *testing.T) {
	srv := storagetest.NewS3(t, testBucket, 2)
	base := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	for i := range 3 {
		srv.Put(fmt.Sprintf("manual/access_review/2026-Q3/page-%d.pdf", i), []byte("%PDF"), base.Add(time.Duration(i)*time.Hour))
	}
	srv.Put("manual/other/2026-Q3/x.pdf", []byte("%PDF"), base)
	r := &manuals3.Reader{Client: srv.Client(), Bucket: testBucket}

	items, err := r.List(context.Background(), "manual/access_review/2026-Q3/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("List returned %d files; want 3: %+v", len(items), items)
	}
	for i, it := range items {
		want := fmt.Sprintf("manual/access_review/2026-Q3/page-%d.pdf", i)
		if it.Key != want || !it.UploadedAt.Equal(base.Add(time.Duration(i)*time.Hour)) {
			t.Errorf("item %d = %+v; want %s uploaded %s", i, it, want, base.Add(time.Duration(i)*time.Hour))
		}
	}
	tokens := srv.PageTokens()
	if len(tokens) != 2 || tokens[0] != "" || tokens[1] == "" {
		t.Errorf("continuation tokens = %q; want a first page and one continued page", tokens)
	}
}

func TestReader_RealSDK_MissingFileIsErrNotFound(t *testing.T) {
	srv := storagetest.NewS3(t, testBucket, 10)
	r := &manuals3.Reader{Client: srv.Client(), Bucket: testBucket}
	_, _, err := r.Get(context.Background(), "manual/policy/2026/missing.pdf")
	if !errors.Is(err, manual.ErrNotFound) {
		t.Errorf("err = %v; want manual.ErrNotFound", err)
	}
}

func TestReader_RealSDK_GetReturnsBodyAndUploadTime(t *testing.T) {
	srv := storagetest.NewS3(t, testBucket, 10)
	uploaded := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	srv.Put("manual/policy/2026/policy.pdf", []byte("%PDF-1.7 body"), uploaded)
	r := &manuals3.Reader{Client: srv.Client(), Bucket: testBucket}

	data, at, err := r.Get(context.Background(), "manual/policy/2026/policy.pdf")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "%PDF-1.7 body" || !at.Equal(uploaded) {
		t.Errorf("Get = %q at %s; want the stored body at %s", data, at, uploaded)
	}
}
