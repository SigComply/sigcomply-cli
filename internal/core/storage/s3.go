package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Backend implements storage using Amazon S3.
type S3Backend struct {
	cfg    *S3Config
	client *s3.Client
}

// NewS3Backend creates a new S3 storage backend.
func NewS3Backend(cfg *S3Config) *S3Backend {
	return &S3Backend{
		cfg: cfg,
	}
}

// Name returns the backend identifier.
func (b *S3Backend) Name() string {
	return "s3"
}

// Init initializes the S3 storage backend.
func (b *S3Backend) Init(ctx context.Context) error {
	var opts []func(*config.LoadOptions) error

	if b.cfg.Region != "" {
		opts = append(opts, config.WithRegion(b.cfg.Region))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	b.client = s3.NewFromConfig(awsCfg)

	// Verify bucket exists by doing a head bucket
	_, err = b.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(b.cfg.Bucket),
	})
	if err != nil {
		return fmt.Errorf("failed to access bucket %s: %w", b.cfg.Bucket, err)
	}

	return nil
}

// StoreRaw saves raw data to S3 at the given path.
func (b *S3Backend) StoreRaw(ctx context.Context, path string, data []byte, metadata map[string]string) (*StoredItem, error) {
	key := buildS3Key(b.cfg.Prefix, path)

	// Upload to S3
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(b.cfg.Bucket),
		Key:         aws.String(key),
		Body:        strings.NewReader(string(data)),
		ContentType: aws.String("application/json"),
		Metadata:    metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload to S3: %w", err)
	}

	// Compute hash
	hash := sha256.Sum256(data)

	return &StoredItem{
		Path:        key,
		Hash:        hex.EncodeToString(hash[:]),
		Size:        int64(len(data)),
		StoredAt:    time.Now().UTC(),
		ContentType: "application/json",
		Metadata:    metadata,
	}, nil
}

// List returns stored items matching the filter.
func (b *S3Backend) List(ctx context.Context, filter *ListFilter) ([]StoredItem, error) {
	var items []StoredItem

	prefix := b.cfg.Prefix
	if filter != nil && filter.Prefix != "" {
		prefix = buildS3Key(b.cfg.Prefix, filter.Prefix)
	}

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(b.cfg.Bucket),
		Prefix: aws.String(prefix),
	}

	if filter != nil && filter.Limit > 0 {
		input.MaxKeys = aws.Int32(int32(filter.Limit))
	}

	paginator := s3.NewListObjectsV2Paginator(b.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list S3 objects: %w", err)
		}

		for i := range page.Contents {
			item := b.convertS3Object(&page.Contents[i], filter)
			if item == nil {
				continue
			}
			items = append(items, *item)

			// Check limit
			if filter != nil && filter.Limit > 0 && len(items) >= filter.Limit {
				return items, nil
			}
		}
	}

	return items, nil
}

// convertS3Object converts an S3 object to a StoredItem, applying filters.
// Returns nil if the object should be filtered out.
func (b *S3Backend) convertS3Object(obj *types.Object, filter *ListFilter) *StoredItem {
	// Apply time filters
	if filter != nil {
		if !filter.After.IsZero() && obj.LastModified.Before(filter.After) {
			return nil
		}
		if !filter.Before.IsZero() && obj.LastModified.After(filter.Before) {
			return nil
		}
	}

	item := &StoredItem{
		Path:     aws.ToString(obj.Key),
		Size:     aws.ToInt64(obj.Size),
		StoredAt: aws.ToTime(obj.LastModified),
	}

	// ETag can be used as hash for non-multipart uploads
	if obj.ETag != nil {
		item.Hash = strings.Trim(*obj.ETag, "\"")
	}

	return item
}

// Get retrieves a stored item by path.
func (b *S3Backend) Get(ctx context.Context, path string) ([]byte, error) {
	result, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.cfg.Bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer result.Body.Close() //nolint:errcheck // closing response body, error is not actionable

	// Read body
	buf := make([]byte, aws.ToInt64(result.ContentLength))
	_, err = result.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("failed to read S3 object: %w", err)
	}

	return buf, nil
}

// Close closes the S3 storage backend (no-op).
func (b *S3Backend) Close() error {
	return nil
}

// buildS3Key constructs an S3 key from path components.
func buildS3Key(parts ...string) string {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, strings.Trim(p, "/"))
		}
	}
	return strings.Join(nonEmpty, "/")
}
