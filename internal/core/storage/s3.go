package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
)

// defaultS3OIDCAudience is the audience requested when fetching a CI OIDC
// token to exchange for AWS credentials via STS AssumeRoleWithWebIdentity.
const defaultS3OIDCAudience = "sts.amazonaws.com"

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
//
// Auth strategy is chosen by b.cfg.Auth:
//   - nil or Mode "ambient":  AWS SDK default credential chain.
//   - Mode "oidc":            STS AssumeRoleWithWebIdentity using the CI OIDC token.
//
// Endpoint and ForcePathStyle are applied for S3-compatible on-prem stores.
func (b *S3Backend) Init(ctx context.Context) error {
	awsCfg, err := b.loadAWSConfig(ctx)
	if err != nil {
		return err
	}

	clientOpts := []func(*s3.Options){}
	if b.cfg.Endpoint != "" {
		endpoint := b.cfg.Endpoint
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}
	if b.cfg.ForcePathStyle {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	b.client = s3.NewFromConfig(awsCfg, clientOpts...)

	// Verify bucket exists by doing a head bucket
	_, err = b.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(b.cfg.Bucket),
	})
	if err != nil {
		return fmt.Errorf("failed to access bucket %s: %w", b.cfg.Bucket, err)
	}

	return nil
}

// loadAWSConfig builds an aws.Config according to the backend's auth mode.
func (b *S3Backend) loadAWSConfig(ctx context.Context) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error
	if b.cfg.Region != "" {
		opts = append(opts, config.WithRegion(b.cfg.Region))
	}

	mode := AuthModeAmbient
	if b.cfg.Auth != nil && b.cfg.Auth.Mode != "" {
		mode = b.cfg.Auth.Mode
	}

	switch mode {
	case AuthModeAmbient:
		awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
		}
		return awsCfg, nil

	case AuthModeOIDC:
		return b.loadAWSConfigOIDC(ctx, opts)

	default:
		return aws.Config{}, fmt.Errorf("unsupported auth mode for S3 backend: %q", b.cfg.Auth.Mode)
	}
}

// loadAWSConfigOIDC obtains a CI OIDC token, exchanges it for AWS credentials
// via STS AssumeRoleWithWebIdentity, and returns an aws.Config carrying those
// credentials.
func (b *S3Backend) loadAWSConfigOIDC(ctx context.Context, baseOpts []func(*config.LoadOptions) error) (aws.Config, error) {
	if b.cfg.Auth == nil || b.cfg.Auth.RoleARN == "" {
		return aws.Config{}, fmt.Errorf("S3 OIDC auth requires auth.role_arn")
	}

	audience := b.cfg.Auth.Audience
	if audience == "" {
		audience = defaultS3OIDCAudience
	}

	token, err := attestation.ObtainOIDCToken(ctx, audience)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to obtain CI OIDC token for S3 auth: %w", err)
	}
	if token == nil || token.Token == "" {
		return aws.Config{}, fmt.Errorf("S3 OIDC auth requested but no CI OIDC provider detected (run inside GitHub Actions or GitLab CI)")
	}

	// Bootstrap an STS client using ambient config so we can reach the STS
	// endpoint (region/proxy/etc. inherited from the environment).
	bootstrapCfg, err := config.LoadDefaultConfig(ctx, baseOpts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load bootstrap AWS config for STS: %w", err)
	}
	stsClient := sts.NewFromConfig(bootstrapCfg)

	sessionName := b.cfg.Auth.SessionName
	if sessionName == "" {
		sessionName = defaultSTSSessionName()
	}

	provider := stscreds.NewWebIdentityRoleProvider(
		stsClient,
		b.cfg.Auth.RoleARN,
		newStaticOIDCTokenRetriever(token.Token),
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = sessionName
		},
	)

	// Reload config with the OIDC-derived credential provider attached.
	credOpts := append(baseOpts, config.WithCredentialsProvider(aws.NewCredentialsCache(provider))) //nolint:gocritic // intentional copy
	awsCfg, err := config.LoadDefaultConfig(ctx, credOpts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config with OIDC credentials: %w", err)
	}
	return awsCfg, nil
}

// staticOIDCTokenRetriever satisfies stscreds.IdentityTokenRetriever by
// returning a token already obtained from the CI OIDC provider.
type staticOIDCTokenRetriever struct {
	token []byte
}

func newStaticOIDCTokenRetriever(token string) *staticOIDCTokenRetriever {
	return &staticOIDCTokenRetriever{token: []byte(token)}
}

// GetIdentityToken returns the cached OIDC token bytes.
func (r *staticOIDCTokenRetriever) GetIdentityToken() ([]byte, error) {
	if len(r.token) == 0 {
		return nil, fmt.Errorf("no OIDC token available")
	}
	return r.token, nil
}

// defaultSTSSessionName returns a deterministic but environment-aware session
// name for AssumeRoleWithWebIdentity calls.
func defaultSTSSessionName() string {
	if v := os.Getenv("GITHUB_REPOSITORY"); v != "" {
		return "sigcomply-" + sanitizeSessionName(v)
	}
	if v := os.Getenv("CI_PROJECT_PATH"); v != "" {
		return "sigcomply-" + sanitizeSessionName(v)
	}
	return "sigcomply-cli"
}

// sanitizeSessionName replaces characters disallowed by STS in
// RoleSessionName ([\w+=,.@-]) with hyphens.
func sanitizeSessionName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '+', c == '=', c == ',', c == '.', c == '@', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return string(out)
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
		input.MaxKeys = aws.Int32(int32(filter.Limit)) //nolint:gosec // filter.Limit is bounded by API design
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
	key := buildS3Key(b.cfg.Prefix, path)
	result, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.cfg.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		// Return NotFoundError for missing keys so callers can use errors.As
		var noSuchKey *types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			return nil, &NotFoundError{Path: path}
		}
		// Also handle the case where S3 returns a generic 404 (some operations)
		if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "StatusCode: 404") {
			return nil, &NotFoundError{Path: path}
		}
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

// URIFor returns a fully-qualified URI for a relative storage path.
// For default AWS S3 (no custom endpoint) the form is "s3://bucket/key".
// For S3-compatible on-prem stores with a custom endpoint, the URI is built
// from the endpoint URL itself (e.g. "https://minio.internal/bucket/key") so
// the user can paste it directly into a browser or `aws s3 cp` command.
func (b *S3Backend) URIFor(path string) string {
	key := buildS3Key(b.cfg.Prefix, path)
	if b.cfg.Endpoint == "" {
		return "s3://" + b.cfg.Bucket + "/" + key
	}
	endpoint := strings.TrimRight(b.cfg.Endpoint, "/")
	if u, err := url.Parse(endpoint); err == nil && u.Scheme != "" && u.Host != "" {
		return endpoint + "/" + b.cfg.Bucket + "/" + key
	}
	// Endpoint is malformed; fall back to the canonical s3:// form so the
	// message remains useful instead of producing a garbled URI.
	return "s3://" + b.cfg.Bucket + "/" + key
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
