// Package s3 implements the manual.pdf Reader on AWS S3 (and S3-compatible stores via Endpoint + ForcePathStyle).
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// API is the subset of the S3 client we use. Defining it as an
// interface lets tests inject a fake without spinning up a real
// bucket. The concrete *s3.Client satisfies it.
type API interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// Reader is the manual.pdf Reader backed by S3. The Bucket is held on
// the Reader so each Get can pass it to the SDK; the key supplied by
// the manual.Plugin is already prefix-resolved.
type Reader struct {
	Client API
	Bucket string
}

// Options is the constructor input for New. Prefix is not used by the
// Reader at runtime (the manual.Plugin already applies it when forming
// the key) but is threaded through register.go so the manual.Plugin
// can build the expected URI.
type Options struct {
	Bucket         string
	Region         string
	Prefix         string
	Endpoint       string
	ForcePathStyle bool
}

// New constructs a Reader with credentials and config from the AWS SDK
// default chain plus the given region/endpoint/path-style settings.
func New(ctx context.Context, opts Options) (*Reader, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(opts.Region))
	if err != nil {
		return nil, fmt.Errorf("manual.pdf s3: load AWS config: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if opts.Endpoint != "" {
			o.BaseEndpoint = &opts.Endpoint
		}
		if opts.ForcePathStyle {
			o.UsePathStyle = true
		}
	})
	return &Reader{
		Client: client,
		Bucket: opts.Bucket,
	}, nil
}

// Get fetches the object at key and returns its bytes plus the
// recorded LastModified timestamp. A NoSuchKey-style response is
// surfaced as manual.ErrNotFound so the manual.Plugin can render a
// structured "expected at: <path>" failure rather than an error.
func (r *Reader) Get(ctx context.Context, key string) (_ []byte, _ time.Time, err error) {
	out, err := r.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &r.Bucket,
		Key:    &key,
	})
	if err != nil {
		if isNotFound(err) {
			return nil, time.Time{}, manual.ErrNotFound
		}
		return nil, time.Time{}, fmt.Errorf("manual.pdf s3: get %s: %w", key, err)
	}
	defer func() {
		err = errors.Join(err, out.Body.Close())
	}()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("manual.pdf s3: read body for %s: %w", key, err)
	}
	var uploadedAt time.Time
	if out.LastModified != nil {
		uploadedAt = *out.LastModified
	}
	return data, uploadedAt, nil
}

// List returns all objects whose key begins with prefix, sorted by key.
func (r *Reader) List(ctx context.Context, prefix string) ([]manual.FileInfo, error) {
	var items []manual.FileInfo
	var continuationToken *string
	for {
		out, err := r.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &r.Bucket,
			Prefix:            &prefix,
			ContinuationToken: continuationToken,
		})
		if err != nil {
			return nil, fmt.Errorf("manual.pdf s3: list %s: %w", prefix, err)
		}
		for _, obj := range out.Contents {
			key := ""
			if obj.Key != nil {
				key = *obj.Key
			}
			var t time.Time
			if obj.LastModified != nil {
				t = *obj.LastModified
			}
			items = append(items, manual.FileInfo{Key: key, UploadedAt: t})
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		continuationToken = out.NextContinuationToken
	}
	return items, nil
}

// isNotFound reports whether the error wraps a NoSuchKey-style S3
// response.
func isNotFound(err error) bool {
	var nfk *types.NoSuchKey
	if errors.As(err, &nfk) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "NoSuchKey" || code == "NotFound" || code == "404"
	}
	return false
}

// Compile-time assertion.
var _ manual.Reader = (*Reader)(nil)
