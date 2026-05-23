// Package gcs implements core.Vault on Google Cloud Storage.
package gcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// API is the package-internal interface the Vault drives. The real
// implementation wraps a *storage.Client; tests use an in-memory fake.
// Decoupling the SDK behind a flat interface keeps the test surface
// small without taking a dependency on fake-gcs-server.
type API interface {
	Put(ctx context.Context, key string, body []byte, contentType string, meta map[string]string) error
	Get(ctx context.Context, key string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
}

// Vault is a GCS-backed core.Vault.
type Vault struct {
	Client API
	Bucket string
	Prefix string
}

// Options is the constructor input for New.
type Options struct {
	Bucket string
	Prefix string
}

// New constructs a Vault using Application Default Credentials.
func New(ctx context.Context, opts Options) (*Vault, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcs vault: new client: %w", err)
	}
	return &Vault{
		Client: &realGCS{bucket: client.Bucket(opts.Bucket)},
		Bucket: opts.Bucket,
		Prefix: opts.Prefix,
	}, nil
}

// Init verifies bucket reachability via a no-op probe list.
func (v *Vault) Init(ctx context.Context) error {
	if v.Bucket == "" {
		return fmt.Errorf("gcs vault: Bucket must be set")
	}
	if _, err := v.Client.List(ctx, v.Prefix); err != nil {
		return fmt.Errorf("gcs vault: probe bucket %s: %w", v.Bucket, err)
	}
	return nil
}

// PutEnvelope marshals e to JSON and writes it.
func (v *Vault) PutEnvelope(ctx context.Context, key string, e *core.Envelope) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("gcs vault: marshal envelope: %w", err)
	}
	return v.Client.Put(ctx, v.fullKey(key), body, "application/json", nil)
}

// PutJSON marshals body and writes it.
func (v *Vault) PutJSON(ctx context.Context, key string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("gcs vault: marshal json for %s: %w", key, err)
	}
	return v.Client.Put(ctx, v.fullKey(key), data, "application/json", nil)
}

// PutBinary uploads raw bytes. The metadata map is stored as GCS
// object metadata.
func (v *Vault) PutBinary(ctx context.Context, key string, body []byte, meta map[string]string) error {
	return v.Client.Put(ctx, v.fullKey(key), body, "application/octet-stream", meta)
}

// GetBinary fetches an object's bytes.
func (v *Vault) GetBinary(ctx context.Context, key string) ([]byte, error) {
	data, err := v.Client.Get(ctx, v.fullKey(key))
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, fmt.Errorf("gcs vault: not found: %s: %w", key, err)
		}
		return nil, fmt.Errorf("gcs vault: get %s: %w", key, err)
	}
	return data, nil
}

// List enumerates objects under prefix.
func (v *Vault) List(ctx context.Context, prefix string) ([]string, error) {
	full := v.fullKey(prefix)
	keys, err := v.Client.List(ctx, full)
	if err != nil {
		return nil, fmt.Errorf("gcs vault: list %s: %w", prefix, err)
	}
	// Strip configured Prefix so callers see vault-relative keys.
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

// realGCS is the production implementation of API. It speaks to GCS
// via the official Go SDK.
type realGCS struct {
	bucket *storage.BucketHandle
}

func (r *realGCS) Put(ctx context.Context, key string, body []byte, contentType string, meta map[string]string) (err error) {
	w := r.bucket.Object(key).NewWriter(ctx)
	w.ContentType = contentType
	if len(meta) > 0 {
		w.Metadata = meta
	}
	defer func() {
		err = errors.Join(err, w.Close())
	}()
	_, err = w.Write(body)
	return err
}

func (r *realGCS) Get(ctx context.Context, key string) (_ []byte, err error) {
	reader, err := r.bucket.Object(key).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, reader.Close())
	}()
	return io.ReadAll(reader)
}

func (r *realGCS) List(ctx context.Context, prefix string) ([]string, error) {
	it := r.bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	var keys []string
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, attrs.Name)
	}
	return keys, nil
}

// Compile-time assertion.
var _ core.Vault = (*Vault)(nil)
