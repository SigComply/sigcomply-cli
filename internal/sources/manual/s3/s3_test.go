package s3_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	manuals3 "github.com/sigcomply/sigcomply-cli/internal/sources/manual/s3"
)

func boolPtr(b bool) *bool           { return &b }
func strPtr(s string) *string        { return &s }
func timePtr(t time.Time) *time.Time { return &t }

// fakeObj is one in-memory S3 object with a recorded upload time.
type fakeObj struct {
	data         []byte
	lastModified time.Time
}

// fakeS3 is an in-memory stand-in for the subset of the S3 API the
// manual.pdf Reader uses. Each test gets a fresh fakeS3 so isolation
// is automatic.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string]fakeObj
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string]fakeObj{}}
}

func (f *fakeS3) GetObject(_ context.Context, in *awss3.GetObjectInput, _ ...func(*awss3.Options)) (*awss3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[*in.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	lm := o.lastModified
	return &awss3.GetObjectOutput{
		Body:         io.NopCloser(bytes.NewReader(o.data)),
		LastModified: &lm,
	}, nil
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *awss3.ListObjectsV2Input, _ ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := ""
	if in.Prefix != nil {
		prefix = *in.Prefix
	}
	var contents []types.Object
	for key, obj := range f.objects {
		if strings.HasPrefix(key, prefix) {
			k := key
			lm := obj.lastModified
			contents = append(contents, types.Object{Key: &k, LastModified: &lm})
		}
	}
	return &awss3.ListObjectsV2Output{
		Contents:    contents,
		IsTruncated: boolPtr(false),
	}, nil
}

// errorAPI is a GetObject/ListObjectsV2 stub that always returns a
// synthetic error unrelated to NoSuchKey.
type errorAPI struct {
	err error
}

func (e *errorAPI) GetObject(_ context.Context, _ *awss3.GetObjectInput, _ ...func(*awss3.Options)) (*awss3.GetObjectOutput, error) {
	return nil, e.err
}

func (e *errorAPI) ListObjectsV2(_ context.Context, _ *awss3.ListObjectsV2Input, _ ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	return nil, e.err
}

func TestReader_Get_Success(t *testing.T) {
	fake := newFakeS3()
	uploaded := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	want := []byte("hello-pdf-bytes")
	fake.objects["k"] = fakeObj{data: want, lastModified: uploaded}

	r := &manuals3.Reader{Client: fake, Bucket: "test-bucket"}
	got, ts, err := r.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("data: got %q, want %q", got, want)
	}
	if !ts.Equal(uploaded) {
		t.Errorf("uploadedAt: got %v, want %v", ts, uploaded)
	}
}

func TestReader_Get_NotFound(t *testing.T) {
	fake := newFakeS3()
	r := &manuals3.Reader{Client: fake, Bucket: "test-bucket"}
	_, _, err := r.Get(context.Background(), "missing")
	if !errors.Is(err, manual.ErrNotFound) {
		t.Fatalf("expected manual.ErrNotFound, got %v", err)
	}
}

func TestReader_Get_OtherErrorSurfaces(t *testing.T) {
	sentinel := errors.New("boom: synthetic transport error")
	r := &manuals3.Reader{Client: &errorAPI{err: sentinel}, Bucket: "test-bucket"}
	_, _, err := r.Get(context.Background(), "k")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, manual.ErrNotFound) {
		t.Fatalf("synthetic error coerced into ErrNotFound: %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected error to wrap sentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), "manual.pdf s3") {
		t.Errorf("error missing backend prefix: %v", err)
	}
}

func TestRegister_Registered(t *testing.T) {
	if _, ok := manual.LookupReader("s3"); !ok {
		t.Error("manual reader \"s3\" not registered (init side-effect missing)")
	}
}

func TestBuild_RejectsMissingBucket(t *testing.T) {
	f, ok := manual.LookupReader("s3")
	if !ok {
		t.Fatal("s3 reader not registered")
	}
	_, _, _, _, err := f(map[string]any{"region": "us-east-1"})
	if err == nil {
		t.Fatal("expected error for missing bucket")
	}
	if !strings.Contains(err.Error(), "bucket") {
		t.Errorf("error should mention \"bucket\", got %v", err)
	}
}

func TestBuild_RejectsMissingRegion(t *testing.T) {
	f, ok := manual.LookupReader("s3")
	if !ok {
		t.Fatal("s3 reader not registered")
	}
	_, _, _, _, err := f(map[string]any{"bucket": "b"})
	if err == nil {
		t.Fatal("expected error for missing region")
	}
	if !strings.Contains(err.Error(), "region") {
		t.Errorf("error should mention \"region\", got %v", err)
	}
}

func TestBuild_DefaultsPrefix(t *testing.T) {
	f, ok := manual.LookupReader("s3")
	if !ok {
		t.Fatal("s3 reader not registered")
	}
	_, scheme, bucket, prefix, err := f(map[string]any{
		"bucket": "b",
		"region": "us-east-1",
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if scheme != "s3" {
		t.Errorf("scheme: got %q, want \"s3\"", scheme)
	}
	if bucket != "b" {
		t.Errorf("bucket: got %q, want \"b\"", bucket)
	}
	if prefix != "manual/" {
		t.Errorf("prefix: got %q, want \"manual/\"", prefix)
	}
}

func TestBuild_PassesEndpointAndPathStyle(t *testing.T) {
	f, ok := manual.LookupReader("s3")
	if !ok {
		t.Fatal("s3 reader not registered")
	}
	_, _, _, _, err := f(map[string]any{
		"bucket":           "b",
		"region":           "us-east-1",
		"endpoint":         "https://minio.local:9000",
		"force_path_style": true,
	})
	if err != nil {
		t.Fatalf("build with endpoint + force_path_style: %v", err)
	}
}

func TestReader_List_ReturnsMatchingKeys(t *testing.T) {
	uploaded := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	fake := newFakeS3()
	fake.objects["manual/ev/2026-Q1/report.pdf"] = fakeObj{data: []byte("x"), lastModified: uploaded}
	fake.objects["manual/ev/2026-Q1/scan.jpg"] = fakeObj{data: []byte("y"), lastModified: uploaded}
	fake.objects["manual/ev/2026-Q2/other.pdf"] = fakeObj{data: []byte("z"), lastModified: uploaded}

	r := &manuals3.Reader{Client: fake, Bucket: "test-bucket"}
	items, err := r.List(context.Background(), "manual/ev/2026-Q1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("List: got %d items, want 2; items: %v", len(items), items)
	}
	for _, item := range items {
		if !strings.HasPrefix(item.Key, "manual/ev/2026-Q1/") {
			t.Errorf("List: unexpected key %q returned for prefix \"manual/ev/2026-Q1/\"", item.Key)
		}
	}
}

func TestReader_List_Empty(t *testing.T) {
	r := &manuals3.Reader{Client: newFakeS3(), Bucket: "test-bucket"}
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
	r := &manuals3.Reader{Client: &errorAPI{err: sentinel}, Bucket: "test-bucket"}
	_, err := r.List(context.Background(), "manual/ev/2026-Q1/")
	if err == nil {
		t.Fatal("List: expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("List: expected error to wrap sentinel, got %v", err)
	}
	_ = strPtr("")
	_ = timePtr(time.Time{})
}
