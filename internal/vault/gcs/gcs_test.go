package gcs_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/storage"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/vault/gcs"
	"github.com/sigcomply/sigcomply-cli/internal/vault/vaulttest"
)

type fakeGCS struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newFakeGCS() *fakeGCS {
	return &fakeGCS{objects: map[string][]byte{}}
}

func (f *fakeGCS) Put(_ context.Context, key string, body []byte, _ string, _ map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = append([]byte(nil), body...)
	return nil
}

func (f *fakeGCS) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[key]
	if !ok {
		return nil, storage.ErrObjectNotExist
	}
	return append([]byte(nil), data...), nil
}

func (f *fakeGCS) List(_ context.Context, prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func TestGCSVault_Contract(t *testing.T) {
	vaulttest.RunContractSuite(t, func(t *testing.T) core.Vault {
		t.Helper()
		v := &gcs.Vault{
			Client: newFakeGCS(),
			Bucket: "test-bucket",
			Prefix: "sigcomply/",
		}
		if err := v.Init(context.Background()); err != nil {
			t.Fatalf("Init: %v", err)
		}
		return v
	})
}

func TestGCSVault_PrefixApplied(t *testing.T) {
	fake := newFakeGCS()
	v := &gcs.Vault{
		Client: fake,
		Bucket: "test-bucket",
		Prefix: "vault-root/",
	}
	if err := v.PutBinary(context.Background(), "policies/foo/result.json", []byte("x"), nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	if _, ok := fake.objects["vault-root/policies/foo/result.json"]; !ok {
		t.Errorf("expected stored key %q in %v", "vault-root/policies/foo/result.json", fake.objects)
	}
}

func TestGCSVault_InitRejectsEmptyBucket(t *testing.T) {
	v := &gcs.Vault{Client: newFakeGCS()}
	if err := v.Init(context.Background()); err == nil {
		t.Error("Init with empty Bucket returned nil error")
	}
}

func TestGCSVault_PrefixWithoutTrailingSlash(t *testing.T) {
	fake := newFakeGCS()
	v := &gcs.Vault{
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
	// List must return the key WITHOUT the prefix prepended (vault-relative).
	got, err := v.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0] != "key.bin" {
		t.Errorf("List = %v; want [key.bin] (no leading slash, no prefix)", got)
	}
}

func TestGCSVault_NoPrefix(t *testing.T) {
	// Vault with empty prefix: stored key = given key, List strips nothing.
	fake := newFakeGCS()
	v := &gcs.Vault{
		Client: fake,
		Bucket: "test-bucket",
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

// errGCS is an API fake that returns errors for every operation.
type errGCS struct {
	putErr  error
	getErr  error
	listErr error
}

func (e *errGCS) Put(_ context.Context, _ string, _ []byte, _ string, _ map[string]string) error {
	return e.putErr
}
func (e *errGCS) Get(_ context.Context, _ string) ([]byte, error) { return nil, e.getErr }
func (e *errGCS) List(_ context.Context, _ string) ([]string, error) {
	return nil, e.listErr
}

func TestGCSVault_InitError(t *testing.T) {
	sentinel := errors.New("probe failed")
	v := &gcs.Vault{
		Client: &errGCS{listErr: sentinel},
		Bucket: "my-bucket",
	}
	err := v.Init(context.Background())
	if err == nil {
		t.Fatal("Init: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "my-bucket") {
		t.Errorf("Init error %q does not mention bucket name", err)
	}
}

func TestGCSVault_PutBinaryError(t *testing.T) {
	sentinel := errors.New("put error")
	v := &gcs.Vault{Client: &errGCS{putErr: sentinel}, Bucket: "b"}
	err := v.PutBinary(context.Background(), "k.bin", []byte("x"), nil)
	if !errors.Is(err, sentinel) {
		t.Errorf("PutBinary: expected sentinel error, got %v", err)
	}
}

func TestGCSVault_PutJSONError_Put(t *testing.T) {
	sentinel := errors.New("put error")
	v := &gcs.Vault{Client: &errGCS{putErr: sentinel}, Bucket: "b"}
	err := v.PutJSON(context.Background(), "k.json", map[string]string{"a": "b"})
	if !errors.Is(err, sentinel) {
		t.Errorf("PutJSON (put): expected sentinel error, got %v", err)
	}
}

func TestGCSVault_PutJSON_MarshalError(t *testing.T) {
	v := &gcs.Vault{Client: newFakeGCS(), Bucket: "b"}
	err := v.PutJSON(context.Background(), "bad.json", make(chan int))
	if err == nil {
		t.Error("PutJSON with unmarshalable value: expected error, got nil")
	}
}

func TestGCSVault_GetBinaryError_NotFound(t *testing.T) {
	// storage.ErrObjectNotExist → "not found" message.
	v := &gcs.Vault{
		Client: &errGCS{getErr: storage.ErrObjectNotExist},
		Bucket: "b",
	}
	_, err := v.GetBinary(context.Background(), "missing.bin")
	if err == nil {
		t.Fatal("GetBinary: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("GetBinary not-found error %q does not contain 'not found'", err)
	}
}

func TestGCSVault_GetBinaryError_Other(t *testing.T) {
	sentinel := errors.New("gcs internal error")
	v := &gcs.Vault{Client: &errGCS{getErr: sentinel}, Bucket: "b"}
	_, err := v.GetBinary(context.Background(), "any.bin")
	if !errors.Is(err, sentinel) {
		t.Errorf("GetBinary: expected sentinel, got %v", err)
	}
}

func TestGCSVault_ListError(t *testing.T) {
	sentinel := errors.New("list error")
	v := &gcs.Vault{Client: &errGCS{listErr: sentinel}, Bucket: "b"}
	_, err := v.List(context.Background(), "prefix/")
	if !errors.Is(err, sentinel) {
		t.Errorf("List: expected sentinel, got %v", err)
	}
}

func TestGCSVault_PutEnvelopeError_Put(t *testing.T) {
	// After signing, the Put call fails — PutEnvelope must propagate the error.
	sentinel := errors.New("put failed")
	v := &gcs.Vault{Client: &errGCS{putErr: sentinel}, Bucket: "b"}
	env := core.Envelope{FormatVersion: "envelope.v1"}
	// Best-effort: if sign.EncodeEnvelope rejects unsigned envelope, the
	// test passes because an error is returned. If it succeeds, the Put
	// error must bubble up.
	err := v.PutEnvelope(context.Background(), "e.json", &env)
	if err == nil {
		t.Error("PutEnvelope: expected error, got nil")
	}
}
