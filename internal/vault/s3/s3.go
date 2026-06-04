// Package s3 implements core.Vault on AWS S3 (and S3-compatible
// stores via Endpoint + ForcePathStyle). The CLI never reads from the
// vault during the same run; GetBinary exists for tooling like the
// auditor verifier (M18) that reads vault contents externally.
package s3

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
)

// API is the subset of the S3 client we use. Defining it as an
// interface lets tests inject a fake without spinning up a real
// bucket. The concrete *s3.Client satisfies it.
type API interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// Vault is an S3-backed core.Vault.
type Vault struct {
	Client         API
	Bucket         string
	Prefix         string // Optional; trailing slash recommended.
	Region         string
	Endpoint       string // For S3-compatible / on-prem stores.
	ForcePathStyle bool
}

// New constructs a Vault with credentials and config from the AWS SDK
// default chain plus the given region/endpoint/path-style settings.
func New(ctx context.Context, opts Options) (*Vault, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(opts.Region))
	if err != nil {
		return nil, fmt.Errorf("s3 vault: load AWS config: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if opts.Endpoint != "" {
			o.BaseEndpoint = &opts.Endpoint
		}
		if opts.ForcePathStyle {
			o.UsePathStyle = true
		}
	})
	return &Vault{
		Client:         client,
		Bucket:         opts.Bucket,
		Prefix:         opts.Prefix,
		Region:         opts.Region,
		Endpoint:       opts.Endpoint,
		ForcePathStyle: opts.ForcePathStyle,
	}, nil
}

// Options is the constructor input for New.
type Options struct {
	Bucket         string
	Region         string
	Prefix         string
	Endpoint       string
	ForcePathStyle bool
}

// Init verifies the bucket is reachable by issuing a no-op list. It
// does not create the bucket — vault buckets are operator-managed.
func (v *Vault) Init(ctx context.Context) error {
	if v.Bucket == "" {
		return fmt.Errorf("s3 vault: Bucket must be set")
	}
	maxKeys := int32(1)
	_, err := v.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  &v.Bucket,
		MaxKeys: &maxKeys,
	})
	if err != nil {
		return fmt.Errorf("s3 vault: probe bucket %s: %w", v.Bucket, err)
	}
	return nil
}

// PutEnvelope writes the envelope as canonical JSON. The on-disk
// bytes are byte-identical to the bytes fed into the signer. The
// envelope must already be signed; PutEnvelope returns an error if
// not.
func (v *Vault) PutEnvelope(ctx context.Context, key string, e *core.Envelope) error {
	body, err := sign.EncodeEnvelope(e)
	if err != nil {
		return fmt.Errorf("s3 vault: encode envelope: %w", err)
	}
	return v.put(ctx, key, body, "application/json", nil)
}

// PutJSON marshals body as JSON and writes it.
func (v *Vault) PutJSON(ctx context.Context, key string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("s3 vault: marshal json for %s: %w", key, err)
	}
	return v.put(ctx, key, data, "application/json", nil)
}

// PutBinary uploads raw bytes. The metadata map is stored as S3 user-
// defined metadata (x-amz-meta-*); S3 lowercases keys on read.
func (v *Vault) PutBinary(ctx context.Context, key string, body []byte, meta map[string]string) error {
	return v.put(ctx, key, body, "application/octet-stream", meta)
}

// GetBinary fetches an object's bytes.
func (v *Vault) GetBinary(ctx context.Context, key string) (_ []byte, err error) {
	fullKey := v.fullKey(key)
	out, err := v.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &v.Bucket,
		Key:    &fullKey,
	})
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("s3 vault: not found: %s: %w", key, err)
		}
		return nil, fmt.Errorf("s3 vault: get %s: %w", key, err)
	}
	defer func() {
		err = errors.Join(err, out.Body.Close())
	}()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("s3 vault: read body for %s: %w", key, err)
	}
	return data, nil
}

// List enumerates keys under prefix. The Prefix configured on the
// vault is automatically prepended.
func (v *Vault) List(ctx context.Context, prefix string) ([]string, error) {
	full := v.fullKey(prefix)
	var (
		keys []string
		cont *string
	)
	for {
		out, err := v.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &v.Bucket,
			Prefix:            &full,
			ContinuationToken: cont,
		})
		if err != nil {
			return nil, fmt.Errorf("s3 vault: list %s: %w", prefix, err)
		}
		for _, obj := range out.Contents {
			if obj.Key == nil {
				continue
			}
			// Strip the configured vault prefix so callers see vault-
			// relative keys, matching the local backend's behavior. Strip
			// the SAME prefix-plus-separator that fullKey prepended on
			// write — stripping bare v.Prefix when it lacks a trailing
			// slash would leave a spurious leading "/" that breaks exact-
			// prefix matching in report and state enumeration.
			k := strings.TrimPrefix(*obj.Key, v.keyPrefix())
			keys = append(keys, k)
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		cont = out.NextContinuationToken
	}
	return keys, nil
}

func (v *Vault) put(ctx context.Context, key string, body []byte, contentType string, meta map[string]string) error {
	full := v.fullKey(key)
	_, err := v.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &v.Bucket,
		Key:         &full,
		Body:        bytes.NewReader(body),
		ContentType: &contentType,
		Metadata:    meta,
	})
	if err != nil {
		return fmt.Errorf("s3 vault: put %s: %w", key, err)
	}
	return nil
}

func (v *Vault) fullKey(key string) string {
	return v.keyPrefix() + key
}

// keyPrefix returns the configured prefix including its trailing
// separator (the exact string fullKey prepends to every stored key), or
// "" when no prefix is set. List strips this same value so round-tripped
// keys stay vault-relative with no leading slash.
func (v *Vault) keyPrefix() string {
	if v.Prefix == "" {
		return ""
	}
	if strings.HasSuffix(v.Prefix, "/") {
		return v.Prefix
	}
	return v.Prefix + "/"
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
var _ core.Vault = (*Vault)(nil)
