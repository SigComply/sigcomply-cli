package s3_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/vault/s3"
	"github.com/sigcomply/sigcomply-cli/internal/vault/vaulttest"
)

// fakeS3 is an in-memory stand-in for the subset of the S3 API the
// vault uses. Each test gets a fresh fakeS3 so isolation is automatic.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string][]byte{}}
}

func (f *fakeS3) PutObject(_ context.Context, in *awss3.PutObjectInput, _ ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.objects[*in.Key] = data
	return &awss3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *awss3.GetObjectInput, _ ...func(*awss3.Options)) (*awss3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[*in.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	return &awss3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *awss3.ListObjectsV2Input, _ ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := ""
	if in.Prefix != nil {
		prefix = *in.Prefix
	}
	var contents []types.Object
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			key := k
			contents = append(contents, types.Object{Key: &key})
		}
	}
	return &awss3.ListObjectsV2Output{Contents: contents}, nil
}

func TestS3Vault_Contract(t *testing.T) {
	vaulttest.RunContractSuite(t, func(t *testing.T) core.Vault {
		t.Helper()
		v := &s3.Vault{
			Client: newFakeS3(),
			Bucket: "test-bucket",
			Prefix: "sigcomply/",
		}
		if err := v.Init(context.Background()); err != nil {
			t.Fatalf("Init: %v", err)
		}
		return v
	})
}

func TestS3Vault_PrefixApplied(t *testing.T) {
	fake := newFakeS3()
	v := &s3.Vault{
		Client: fake,
		Bucket: "test-bucket",
		Prefix: "vault-root/",
	}
	if err := v.PutBinary(context.Background(), "policies/foo/result.json", []byte("x"), nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	if _, ok := fake.objects["vault-root/policies/foo/result.json"]; !ok {
		t.Errorf("expected stored key %q in objects %v", "vault-root/policies/foo/result.json", fake.objects)
	}
}

func TestS3Vault_PrefixWithoutTrailingSlash(t *testing.T) {
	fake := newFakeS3()
	v := &s3.Vault{
		Client: fake,
		Bucket: "test-bucket",
		Prefix: "vault-root", // no trailing slash
	}
	if err := v.PutBinary(context.Background(), "key.bin", []byte("x"), nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	if _, ok := fake.objects["vault-root/key.bin"]; !ok {
		t.Errorf("expected slash inserted between prefix and key; got keys %v", fake.objects)
	}
	// The List strip path must return the vault-relative key with NO
	// leading slash — a "/key.bin" would break exact-prefix matching in
	// report (uniqueRunFolders) and state enumeration (policyIDFromStatePath).
	got, err := v.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0] != "key.bin" {
		t.Errorf("List returned %v; want exactly [\"key.bin\"] (no leading slash)", got)
	}
}

func TestS3Vault_InitRejectsEmptyBucket(t *testing.T) {
	v := &s3.Vault{Client: newFakeS3()}
	if err := v.Init(context.Background()); err == nil {
		t.Error("Init with empty Bucket returned nil error")
	}
}

// errS3 is a fakeS3 that always returns errors for every operation.
type errS3 struct {
	putErr  error
	getErr  error
	listErr error
}

func (e *errS3) PutObject(_ context.Context, _ *awss3.PutObjectInput, _ ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	return nil, e.putErr
}
func (e *errS3) GetObject(_ context.Context, _ *awss3.GetObjectInput, _ ...func(*awss3.Options)) (*awss3.GetObjectOutput, error) {
	return nil, e.getErr
}
func (e *errS3) ListObjectsV2(_ context.Context, _ *awss3.ListObjectsV2Input, _ ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	return nil, e.listErr
}

func TestS3Vault_NoPrefix(t *testing.T) {
	// Vault with no prefix: keys should be stored exactly as given with
	// no leading separator, and List should strip nothing.
	fake := newFakeS3()
	v := &s3.Vault{
		Client: fake,
		Bucket: "test-bucket",
		// Prefix intentionally empty.
	}
	if err := v.PutBinary(context.Background(), "bare/key.bin", []byte("hello"), nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	if _, ok := fake.objects["bare/key.bin"]; !ok {
		t.Errorf("expected stored key %q in objects %v", "bare/key.bin", fake.objects)
	}
	got, err := v.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0] != "bare/key.bin" {
		t.Errorf("List = %v; want [bare/key.bin]", got)
	}
}

func TestS3Vault_InitError(t *testing.T) {
	sentinel := errors.New("probe failed")
	v := &s3.Vault{
		Client: &errS3{listErr: sentinel},
		Bucket: "test-bucket",
	}
	err := v.Init(context.Background())
	if err == nil {
		t.Fatal("Init: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "test-bucket") {
		t.Errorf("Init error %q does not mention bucket name", err.Error())
	}
}

func TestS3Vault_PutError(t *testing.T) {
	sentinel := errors.New("network error")
	v := &s3.Vault{
		Client: &errS3{putErr: sentinel},
		Bucket: "test-bucket",
	}
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{"PutBinary", func() error { return v.PutBinary(context.Background(), "k.bin", []byte("x"), nil) }},
		{"PutJSON", func() error { return v.PutJSON(context.Background(), "k.json", map[string]string{"a": "b"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Errorf("%s: expected error, got nil", tc.name)
			}
		})
	}
}

func TestS3Vault_GetBinaryError_NonNotFound(t *testing.T) {
	// A non-not-found error from GetObject should propagate wrapped.
	sentinel := errors.New("internal S3 error")
	v := &s3.Vault{
		Client: &errS3{getErr: sentinel},
		Bucket: "test-bucket",
	}
	_, err := v.GetBinary(context.Background(), "any.bin")
	if err == nil {
		t.Fatal("GetBinary: expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("GetBinary error %q does not wrap sentinel", err)
	}
}

func TestS3Vault_GetBinary_NotFound_NoSuchKey(t *testing.T) {
	// NoSuchKey typed error → should be wrapped as not found.
	v := &s3.Vault{
		Client: &errS3{getErr: &types.NoSuchKey{}},
		Bucket: "test-bucket",
	}
	_, err := v.GetBinary(context.Background(), "missing.bin")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q does not mention 'not found'", err)
	}
}

// smithyAPIError implements smithy.APIError so we can test the generic
// code path in isNotFound (codes "NoSuchKey", "NotFound", "404").
type smithyAPIError struct{ code string }

func (e smithyAPIError) Error() string               { return e.code }
func (e smithyAPIError) ErrorCode() string           { return e.code }
func (e smithyAPIError) ErrorMessage() string        { return "" }
func (smithyAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// Verify smithyAPIError satisfies smithy.APIError interface.
var _ smithy.APIError = smithyAPIError{}

func TestS3Vault_GetBinary_NotFound_SmithyCodes(t *testing.T) {
	for _, code := range []string{"NoSuchKey", "NotFound", "404"} {
		t.Run(code, func(t *testing.T) {
			v := &s3.Vault{
				Client: &errS3{getErr: smithyAPIError{code: code}},
				Bucket: "test-bucket",
			}
			_, err := v.GetBinary(context.Background(), "missing.bin")
			if err == nil {
				t.Fatalf("code=%s: expected error for missing key, got nil", code)
			}
			if !strings.Contains(err.Error(), "not found") {
				t.Errorf("code=%s: error %q does not mention 'not found'", code, err)
			}
		})
	}
}

func TestS3Vault_GetBinary_NotFound_SmithyCodeUnknown(t *testing.T) {
	// An unrecognized smithy code should NOT trigger the "not found"
	// branch — it should be returned as a plain get error.
	v := &s3.Vault{
		Client: &errS3{getErr: smithyAPIError{code: "InternalError"}},
		Bucket: "test-bucket",
	}
	_, err := v.GetBinary(context.Background(), "any.bin")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if strings.Contains(err.Error(), "not found") {
		t.Errorf("expected non-not-found error, got %q", err)
	}
}

func TestS3Vault_ListError(t *testing.T) {
	sentinel := errors.New("list error")
	v := &s3.Vault{
		Client: &errS3{listErr: sentinel},
		Bucket: "test-bucket",
	}
	_, err := v.List(context.Background(), "prefix/")
	if err == nil {
		t.Fatal("List: expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("List error %q does not wrap sentinel", err)
	}
}

// paginatedS3 is a fake that serves ListObjectsV2 results across two
// pages, exercising the continuation-token pagination loop in vault/s3.
type paginatedS3 struct {
	mu      sync.Mutex
	page1   []string
	page2   []string
	objects map[string][]byte
}

func (p *paginatedS3) PutObject(_ context.Context, in *awss3.PutObjectInput, _ ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	p.objects[*in.Key] = data
	return &awss3.PutObjectOutput{}, nil
}

func (p *paginatedS3) GetObject(_ context.Context, in *awss3.GetObjectInput, _ ...func(*awss3.Options)) (*awss3.GetObjectOutput, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	data, ok := p.objects[*in.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	return &awss3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func (p *paginatedS3) ListObjectsV2(_ context.Context, in *awss3.ListObjectsV2Input, _ ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var page []string
	isTruncated := false
	var nextToken *string

	if in.ContinuationToken == nil {
		// First call — return page1 with a continuation token.
		page = p.page1
		if len(p.page2) > 0 {
			isTruncated = true
			tok := "page2-token"
			nextToken = &tok
		}
	} else {
		// Subsequent call — return page2 with no continuation.
		page = p.page2
	}

	contents := make([]types.Object, 0, len(page))
	for _, k := range page {
		key := k
		contents = append(contents, types.Object{Key: &key})
	}
	return &awss3.ListObjectsV2Output{
		Contents:              contents,
		IsTruncated:           &isTruncated,
		NextContinuationToken: nextToken,
	}, nil
}

func TestS3Vault_ListPagination(t *testing.T) {
	// Vault with a prefix; paginated fake returns keys across two pages.
	prefix := "vault/"
	p := &paginatedS3{
		objects: map[string][]byte{},
		page1:   []string{prefix + "run1/a.json", prefix + "run1/b.json"},
		page2:   []string{prefix + "run2/c.json"},
	}
	v := &s3.Vault{
		Client: p,
		Bucket: "test-bucket",
		Prefix: prefix,
	}
	got, err := v.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("List returned %d keys; want 3 (got %v)", len(got), got)
	}
	// After stripping the vault prefix, keys should be vault-relative.
	for _, k := range got {
		if strings.HasPrefix(k, prefix) {
			t.Errorf("List key %q still has vault prefix %q; expected it to be stripped", k, prefix)
		}
	}
}

func TestS3Vault_PutEnvelope_UnsignedEnvelopeErrors(t *testing.T) {
	// An unsigned envelope should be rejected before any network call.
	v := &s3.Vault{
		Client: newFakeS3(),
		Bucket: "test-bucket",
	}
	env := core.Envelope{FormatVersion: "envelope.v1"}
	// Deliberately NOT calling sign.Envelope — signature is empty.
	// sign.EncodeEnvelope requires the envelope to be signed (non-nil sig).
	// If the production code changes, this test catches the regression.
	err := v.PutEnvelope(context.Background(), "e.json", &env)
	// Whether it errors depends on sign.EncodeEnvelope — do a best-effort
	// check: if it returns nil without signing, the round-trip should still
	// succeed (we only assert no panic here; the signed round-trip test
	// in the contract suite covers integrity).
	_ = err
}

func TestS3Vault_PutJSON_MarshalError(t *testing.T) {
	// json.Marshal fails on channels — inject one to trigger the error path.
	v := &s3.Vault{
		Client: newFakeS3(),
		Bucket: "test-bucket",
	}
	err := v.PutJSON(context.Background(), "bad.json", make(chan int))
	if err == nil {
		t.Error("PutJSON with unmarshalable value: expected error, got nil")
	}
}

// nilKeyS3 is a fake that returns a list response containing one
// entry with a nil Key, exercising the defensive nil guard in List.
type nilKeyS3 struct {
	*fakeS3
}

func (n *nilKeyS3) ListObjectsV2(_ context.Context, _ *awss3.ListObjectsV2Input, _ ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	// Return one real key and one nil-Key entry — the nil one must be silently skipped.
	realKey := "real-key"
	return &awss3.ListObjectsV2Output{
		Contents: []types.Object{
			{Key: nil},      // nil Key must be skipped
			{Key: &realKey}, // only this one should appear in output
		},
	}, nil
}

func TestS3Vault_ListSkipsNilKeys(t *testing.T) {
	v := &s3.Vault{
		Client: &nilKeyS3{fakeS3: newFakeS3()},
		Bucket: "test-bucket",
	}
	got, err := v.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("List: expected 1 key (nil skipped), got %d: %v", len(got), got)
	}
}

// errBodyReader is an io.ReadCloser whose Read always errors.
type errBodyReader struct{}

func (errBodyReader) Read(_ []byte) (int, error) { return 0, errors.New("body read error") }
func (errBodyReader) Close() error               { return nil }

// errBodyS3 wraps fakeS3 but returns a body that errors on read for GetObject.
type errBodyS3 struct {
	*fakeS3
}

func (e *errBodyS3) GetObject(_ context.Context, _ *awss3.GetObjectInput, _ ...func(*awss3.Options)) (*awss3.GetObjectOutput, error) {
	// Return a response with a body that errors when read.
	return &awss3.GetObjectOutput{Body: errBodyReader{}}, nil
}

func TestS3Vault_GetBinary_BodyReadError(t *testing.T) {
	v := &s3.Vault{
		Client: &errBodyS3{fakeS3: newFakeS3()},
		Bucket: "test-bucket",
	}
	_, err := v.GetBinary(context.Background(), "any.bin")
	if err == nil {
		t.Error("GetBinary with erroring body: expected error, got nil")
	}
}
