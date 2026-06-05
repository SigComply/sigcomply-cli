package azureblob_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/vault/azureblob"
	"github.com/sigcomply/sigcomply-cli/internal/vault/vaulttest"
)

type fakeAzure struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newFakeAzure() *fakeAzure {
	return &fakeAzure{objects: map[string][]byte{}}
}

func (f *fakeAzure) Put(_ context.Context, key string, body []byte, _ map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = append([]byte(nil), body...)
	return nil
}

func (f *fakeAzure) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[key]
	if !ok {
		return nil, azureblob.ErrNotFound
	}
	return append([]byte(nil), data...), nil
}

func (f *fakeAzure) List(_ context.Context, prefix string) ([]string, error) {
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

func TestAzureBlobVault_Contract(t *testing.T) {
	vaulttest.RunContractSuite(t, func(t *testing.T) core.Vault {
		t.Helper()
		v := &azureblob.Vault{
			Client:    newFakeAzure(),
			Account:   "test-account",
			Container: "test-container",
			Prefix:    "sigcomply/",
		}
		if err := v.Init(context.Background()); err != nil {
			t.Fatalf("Init: %v", err)
		}
		return v
	})
}

func TestAzureBlobVault_PrefixApplied(t *testing.T) {
	fake := newFakeAzure()
	v := &azureblob.Vault{
		Client:    fake,
		Container: "c",
		Prefix:    "vault-root/",
	}
	if err := v.PutBinary(context.Background(), "policies/foo/result.json", []byte("x"), nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	if _, ok := fake.objects["vault-root/policies/foo/result.json"]; !ok {
		t.Errorf("expected stored key %q in %v", "vault-root/policies/foo/result.json", fake.objects)
	}
}

func TestAzureBlobVault_InitRejectsEmptyContainer(t *testing.T) {
	v := &azureblob.Vault{Client: newFakeAzure()}
	if err := v.Init(context.Background()); err == nil {
		t.Error("Init with empty Container returned nil error")
	}
}

func TestAzureBlobVault_PrefixWithoutTrailingSlash(t *testing.T) {
	fake := newFakeAzure()
	v := &azureblob.Vault{
		Client:    fake,
		Container: "c",
		Prefix:    "vault-root", // no trailing slash
	}
	if err := v.PutBinary(context.Background(), "key.bin", []byte("x"), nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	if _, ok := fake.objects["vault-root/key.bin"]; !ok {
		t.Errorf("expected slash inserted between prefix and key; got keys %v", fake.objects)
	}
	// List must return vault-relative key with NO leading slash.
	got, err := v.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0] != "key.bin" {
		t.Errorf("List = %v; want [key.bin] (no leading slash, no prefix)", got)
	}
}

func TestAzureBlobVault_NoPrefix(t *testing.T) {
	// Empty prefix: stored key = given key; List strips nothing.
	fake := newFakeAzure()
	v := &azureblob.Vault{
		Client:    fake,
		Container: "c",
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

// errAzure is an API fake that returns errors for every operation.
type errAzure struct {
	putErr  error
	getErr  error
	listErr error
}

func (e *errAzure) Put(_ context.Context, _ string, _ []byte, _ map[string]string) error {
	return e.putErr
}
func (e *errAzure) Get(_ context.Context, _ string) ([]byte, error) { return nil, e.getErr }
func (e *errAzure) List(_ context.Context, _ string) ([]string, error) {
	return nil, e.listErr
}

func TestAzureBlobVault_InitError(t *testing.T) {
	sentinel := errors.New("probe failed")
	v := &azureblob.Vault{
		Client:    &errAzure{listErr: sentinel},
		Container: "my-container",
	}
	err := v.Init(context.Background())
	if err == nil {
		t.Fatal("Init: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "my-container") {
		t.Errorf("Init error %q does not mention container name", err)
	}
}

func TestAzureBlobVault_PutBinaryError(t *testing.T) {
	sentinel := errors.New("put error")
	v := &azureblob.Vault{Client: &errAzure{putErr: sentinel}, Container: "c"}
	err := v.PutBinary(context.Background(), "k.bin", []byte("x"), nil)
	if !errors.Is(err, sentinel) {
		t.Errorf("PutBinary: expected sentinel error, got %v", err)
	}
}

func TestAzureBlobVault_PutJSONError_Put(t *testing.T) {
	sentinel := errors.New("put error")
	v := &azureblob.Vault{Client: &errAzure{putErr: sentinel}, Container: "c"}
	err := v.PutJSON(context.Background(), "k.json", map[string]string{"a": "b"})
	if !errors.Is(err, sentinel) {
		t.Errorf("PutJSON (put): expected sentinel error, got %v", err)
	}
}

func TestAzureBlobVault_PutJSON_MarshalError(t *testing.T) {
	v := &azureblob.Vault{Client: newFakeAzure(), Container: "c"}
	err := v.PutJSON(context.Background(), "bad.json", make(chan int))
	if err == nil {
		t.Error("PutJSON with unmarshalable value: expected error, got nil")
	}
}

func TestAzureBlobVault_GetBinaryError_NotFound(t *testing.T) {
	// ErrNotFound sentinel → "not found" message.
	v := &azureblob.Vault{
		Client:    &errAzure{getErr: azureblob.ErrNotFound},
		Container: "c",
	}
	_, err := v.GetBinary(context.Background(), "missing.bin")
	if err == nil {
		t.Fatal("GetBinary: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("GetBinary not-found error %q does not contain 'not found'", err)
	}
}

func TestAzureBlobVault_GetBinaryError_Other(t *testing.T) {
	sentinel := errors.New("azure internal error")
	v := &azureblob.Vault{Client: &errAzure{getErr: sentinel}, Container: "c"}
	_, err := v.GetBinary(context.Background(), "any.bin")
	if !errors.Is(err, sentinel) {
		t.Errorf("GetBinary: expected sentinel, got %v", err)
	}
}

func TestAzureBlobVault_ListError(t *testing.T) {
	sentinel := errors.New("list error")
	v := &azureblob.Vault{Client: &errAzure{listErr: sentinel}, Container: "c"}
	_, err := v.List(context.Background(), "prefix/")
	if !errors.Is(err, sentinel) {
		t.Errorf("List: expected sentinel, got %v", err)
	}
}

func TestAzureBlobVault_PutEnvelopeError_Put(t *testing.T) {
	// After encoding, the Put call fails — PutEnvelope must propagate the error.
	sentinel := errors.New("put failed")
	v := &azureblob.Vault{Client: &errAzure{putErr: sentinel}, Container: "c"}
	env := core.Envelope{FormatVersion: "envelope.v1"}
	err := v.PutEnvelope(context.Background(), "e.json", &env)
	if err == nil {
		t.Error("PutEnvelope: expected error, got nil")
	}
}
