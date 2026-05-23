package azureblob_test

import (
	"context"
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
