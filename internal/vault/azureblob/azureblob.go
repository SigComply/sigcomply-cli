// Package azureblob implements core.Vault on Azure Blob Storage.
package azureblob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// API is the package-internal interface the Vault drives. Tests
// inject an in-memory fake; production wires in the SDK adapter
// declared below.
type API interface {
	Put(ctx context.Context, key string, body []byte, meta map[string]string) error
	Get(ctx context.Context, key string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
}

// Vault is an Azure-Blob-backed core.Vault.
type Vault struct {
	Client    API
	Account   string
	Container string
	Prefix    string
}

// Options is the constructor input for New.
type Options struct {
	Account   string
	Container string
	Prefix    string
}

// New constructs a Vault using DefaultAzureCredential.
func New(_ context.Context, opts Options) (*Vault, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure blob vault: credentials: %w", err)
	}
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", opts.Account)
	svc, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure blob vault: new client: %w", err)
	}
	return &Vault{
		Client:    &realAzure{svc: svc, container: opts.Container},
		Account:   opts.Account,
		Container: opts.Container,
		Prefix:    opts.Prefix,
	}, nil
}

// Init verifies the container is reachable.
func (v *Vault) Init(ctx context.Context) error {
	if v.Container == "" {
		return fmt.Errorf("azure blob vault: Container must be set")
	}
	if _, err := v.Client.List(ctx, v.Prefix); err != nil {
		return fmt.Errorf("azure blob vault: probe container %s: %w", v.Container, err)
	}
	return nil
}

// PutEnvelope marshals e and writes it.
func (v *Vault) PutEnvelope(ctx context.Context, key string, e *core.Envelope) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("azure blob vault: marshal envelope: %w", err)
	}
	return v.Client.Put(ctx, v.fullKey(key), body, nil)
}

// PutJSON marshals body and writes it.
func (v *Vault) PutJSON(ctx context.Context, key string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("azure blob vault: marshal json for %s: %w", key, err)
	}
	return v.Client.Put(ctx, v.fullKey(key), data, nil)
}

// PutBinary uploads raw bytes. The metadata map is stored as blob
// metadata.
func (v *Vault) PutBinary(ctx context.Context, key string, body []byte, meta map[string]string) error {
	return v.Client.Put(ctx, v.fullKey(key), body, meta)
}

// GetBinary fetches a blob's bytes.
func (v *Vault) GetBinary(ctx context.Context, key string) ([]byte, error) {
	data, err := v.Client.Get(ctx, v.fullKey(key))
	if err != nil {
		if errors.Is(err, ErrNotFound) || bloberror.HasCode(err, bloberror.BlobNotFound) {
			return nil, fmt.Errorf("azure blob vault: not found: %s: %w", key, err)
		}
		return nil, fmt.Errorf("azure blob vault: get %s: %w", key, err)
	}
	return data, nil
}

// List enumerates blobs under prefix.
func (v *Vault) List(ctx context.Context, prefix string) ([]string, error) {
	full := v.fullKey(prefix)
	keys, err := v.Client.List(ctx, full)
	if err != nil {
		return nil, fmt.Errorf("azure blob vault: list %s: %w", prefix, err)
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, v.Prefix))
	}
	return out, nil
}

func (v *Vault) fullKey(key string) string {
	if v.Prefix == "" {
		return key
	}
	if strings.HasSuffix(v.Prefix, "/") {
		return v.Prefix + key
	}
	return v.Prefix + "/" + key
}

// ErrNotFound is the sentinel a fake test impl can return; the real
// adapter relies on the SDK's typed errors via bloberror.HasCode.
var ErrNotFound = errors.New("blob not found")

// realAzure is the production implementation of API. It wraps the
// azblob SDK client.
type realAzure struct {
	svc       *azblob.Client
	container string
}

func (r *realAzure) Put(ctx context.Context, key string, body []byte, meta map[string]string) error {
	var opts *azblob.UploadBufferOptions
	if len(meta) > 0 {
		opts = &azblob.UploadBufferOptions{
			Metadata: stringPointerMap(meta),
		}
	}
	_, err := r.svc.UploadBuffer(ctx, r.container, key, body, opts)
	return err
}

func (r *realAzure) Get(ctx context.Context, key string) (_ []byte, err error) {
	resp, err := r.svc.DownloadStream(ctx, r.container, key, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, resp.Body.Close())
	}()
	return io.ReadAll(resp.Body)
}

func (r *realAzure) List(ctx context.Context, prefix string) ([]string, error) {
	pager := r.svc.NewListBlobsFlatPager(r.container, &container.ListBlobsFlatOptions{
		Prefix: stringPtr(prefix),
	})
	var keys []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, b := range page.Segment.BlobItems {
			if b == nil || b.Name == nil {
				continue
			}
			keys = append(keys, *b.Name)
		}
	}
	return keys, nil
}

func stringPtr(s string) *string { return &s }

func stringPointerMap(m map[string]string) map[string]*string {
	out := make(map[string]*string, len(m))
	for k, v := range m {
		vv := v
		out[k] = &vv
	}
	return out
}

// Compile-time assertion.
var _ core.Vault = (*Vault)(nil)
