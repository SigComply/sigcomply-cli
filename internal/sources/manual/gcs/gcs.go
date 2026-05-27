// Package gcs implements the manual.pdf Reader on Google Cloud Storage.
package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// API is the package-internal interface the Reader drives. Unlike the
// vault GCS backend's flatter Put/Get/List shape, the manual Reader
// contract requires the upload time alongside the bytes, so Get here
// returns (data, updatedAt, err) directly. The concrete implementation
// wraps a *storage.BucketHandle; tests inject an in-memory fake.
type API interface {
	Get(ctx context.Context, key string) ([]byte, time.Time, error)
	List(ctx context.Context, prefix string) ([]manual.FileInfo, error)
}

// Reader is the manual.pdf Reader backed by GCS. The Bucket is held on
// the Reader for diagnostics; the SDK call is bucket-scoped via the
// underlying handle held by realGCS.
type Reader struct {
	Client API
	Bucket string
}

// Options is the constructor input for New. Prefix is not used by the
// Reader at runtime (the manual.Plugin already applies it when forming
// the key) but is threaded through register.go so the manual.Plugin
// can build the expected URI.
type Options struct {
	Bucket string
	Prefix string
}

// New constructs a Reader using Application Default Credentials, the
// same auth path as the vault GCS backend.
func New(ctx context.Context, opts Options) (*Reader, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("manual.pdf gcs: new client: %w", err)
	}
	return &Reader{
		Client: &realGCS{bucket: client.Bucket(opts.Bucket)},
		Bucket: opts.Bucket,
	}, nil
}

// Get fetches the object at key and returns its bytes plus the
// recorded LastModified timestamp. A storage.ErrObjectNotExist is
// surfaced as manual.ErrNotFound so the manual.Plugin can render a
// structured "expected at: <path>" failure rather than an error.
func (r *Reader) Get(ctx context.Context, key string) ([]byte, time.Time, error) {
	data, uploadedAt, err := r.Client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, time.Time{}, manual.ErrNotFound
		}
		return nil, time.Time{}, fmt.Errorf("manual.pdf gcs: get %s: %w", key, err)
	}
	return data, uploadedAt, nil
}

// List returns all objects whose key begins with prefix, sorted by key.
func (r *Reader) List(ctx context.Context, prefix string) ([]manual.FileInfo, error) {
	items, err := r.Client.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("manual.pdf gcs: list %s: %w", prefix, err)
	}
	return items, nil
}

// realGCS is the production implementation of API. It speaks to GCS
// via the official Go SDK using a single NewReader round-trip; the
// Reader's Attrs field exposes LastModified without a second Attrs
// call.
type realGCS struct {
	bucket *storage.BucketHandle
}

func (r *realGCS) Get(ctx context.Context, key string) (_ []byte, _ time.Time, err error) {
	reader, err := r.bucket.Object(key).NewReader(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() {
		err = errors.Join(err, reader.Close())
	}()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, reader.Attrs.LastModified.UTC(), nil
}

func (r *realGCS) List(ctx context.Context, prefix string) ([]manual.FileInfo, error) {
	var items []manual.FileInfo
	it := r.bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		items = append(items, manual.FileInfo{Key: attrs.Name, UploadedAt: attrs.Updated.UTC()})
	}
	return items, nil
}

// Compile-time assertion.
var _ manual.Reader = (*Reader)(nil)
