package gcs_test

import (
	"context"
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
