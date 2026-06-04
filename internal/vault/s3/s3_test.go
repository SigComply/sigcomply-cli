package s3_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

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
