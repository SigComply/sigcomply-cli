// Package azureblob implements the manual.pdf Reader on Azure Blob Storage.
package azureblob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// API is the package-internal interface the Reader drives. Tests
// inject an in-memory fake; production wires in the SDK adapter
// declared below.
type API interface {
	Get(ctx context.Context, key string) ([]byte, time.Time, error)
	List(ctx context.Context, prefix string) ([]manual.FileInfo, error)
}

// Reader is an Azure-Blob-backed manual.Reader.
type Reader struct {
	Client    API
	Account   string
	Container string
}

// Options is the constructor input for New.
type Options struct {
	Account   string
	Container string
	Prefix    string
}

// New constructs a Reader using DefaultAzureCredential.
func New(_ context.Context, opts Options) (*Reader, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("manual.pdf azureblob: credentials: %w", err)
	}
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", opts.Account)
	svc, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("manual.pdf azureblob: new client: %w", err)
	}
	return &Reader{
		Client:    &realAzure{svc: svc, container: opts.Container},
		Account:   opts.Account,
		Container: opts.Container,
	}, nil
}

// Get returns the bytes and upload time at key, translating Azure's
// not-found signals into manual.ErrNotFound.
func (r *Reader) Get(ctx context.Context, key string) ([]byte, time.Time, error) {
	data, uploadedAt, err := r.Client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) || bloberror.HasCode(err, bloberror.BlobNotFound) {
			return nil, time.Time{}, manual.ErrNotFound
		}
		return nil, time.Time{}, fmt.Errorf("manual.pdf azureblob: get %s: %w", key, err)
	}
	return data, uploadedAt, nil
}

// List returns all blobs whose key begins with prefix, sorted by key.
func (r *Reader) List(ctx context.Context, prefix string) ([]manual.FileInfo, error) {
	items, err := r.Client.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("manual.pdf azureblob: list %s: %w", prefix, err)
	}
	return items, nil
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

func (r *realAzure) Get(ctx context.Context, key string) (_ []byte, _ time.Time, err error) {
	resp, err := r.svc.DownloadStream(ctx, r.container, key, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() {
		err = errors.Join(err, resp.Body.Close())
	}()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Time{}, err
	}
	var lastMod time.Time
	if resp.LastModified != nil {
		lastMod = *resp.LastModified
	}
	return data, lastMod, nil
}

func (r *realAzure) List(ctx context.Context, prefix string) ([]manual.FileInfo, error) {
	var items []manual.FileInfo
	pager := r.svc.NewListBlobsFlatPager(r.container, &azblob.ListBlobsFlatOptions{
		Prefix: &prefix,
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, blob := range page.Segment.BlobItems {
			name := ""
			if blob.Name != nil {
				name = *blob.Name
			}
			var t time.Time
			if blob.Properties != nil && blob.Properties.LastModified != nil {
				t = *blob.Properties.LastModified
			}
			items = append(items, manual.FileInfo{Key: name, UploadedAt: t})
		}
	}
	return items, nil
}

// Compile-time assertion.
var _ manual.Reader = (*Reader)(nil)
