package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
)

const (
	// gcsSTSTokenURL is the Google STS endpoint that exchanges a federated
	// subject token (the CI OIDC JWT) for a federated GCP access token.
	gcsSTSTokenURL = "https://sts.googleapis.com/v1/token"

	// gcsSubjectTokenType is the OAuth 2.0 token-exchange subject type
	// for JWT-shaped tokens (which both GitHub Actions and GitLab issue).
	gcsSubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"

	// gcsImpersonationURLTemplate produces the iamcredentials URL that
	// turns a federated token into an access token for the configured
	// service account. %s is the service account email.
	gcsImpersonationURLTemplate = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
)

// GCSBackend implements storage using Google Cloud Storage.
type GCSBackend struct {
	cfg    *GCSConfig
	client *storage.Client
}

// NewGCSBackend creates a new GCS storage backend.
func NewGCSBackend(cfg *GCSConfig) *GCSBackend {
	return &GCSBackend{cfg: cfg}
}

// Name returns the backend identifier.
func (b *GCSBackend) Name() string { return "gcs" }

// Init initializes the GCS storage backend, choosing an auth strategy from
// b.cfg.Auth. When Auth is nil or Mode is "ambient", Application Default
// Credentials are used. When Mode is "oidc", the CLI exchanges its CI OIDC
// token for a federated access token via Workload Identity Federation.
func (b *GCSBackend) Init(ctx context.Context) error {
	clientOpts, err := b.clientOptions(ctx)
	if err != nil {
		return err
	}

	client, err := storage.NewClient(ctx, clientOpts...)
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	b.client = client

	// Verify bucket access by reading attributes.
	if _, err := b.client.Bucket(b.cfg.Bucket).Attrs(ctx); err != nil {
		return fmt.Errorf("failed to access GCS bucket %s: %w", b.cfg.Bucket, err)
	}
	return nil
}

// clientOptions builds the option.ClientOption slice for storage.NewClient
// based on the backend's auth mode.
func (b *GCSBackend) clientOptions(ctx context.Context) ([]option.ClientOption, error) {
	mode := AuthModeAmbient
	if b.cfg.Auth != nil && b.cfg.Auth.Mode != "" {
		mode = b.cfg.Auth.Mode
	}

	switch mode {
	case AuthModeAmbient:
		// No options — the client uses Application Default Credentials.
		return nil, nil

	case AuthModeOIDC:
		return b.oidcClientOptions(ctx)

	default:
		return nil, fmt.Errorf("unsupported auth mode for GCS backend: %q", b.cfg.Auth.Mode)
	}
}

// oidcClientOptions builds an externalaccount-based credential that
// exchanges the in-memory CI OIDC token for a federated GCP token, then
// impersonates the configured service account.
func (b *GCSBackend) oidcClientOptions(ctx context.Context) ([]option.ClientOption, error) {
	if b.cfg.Auth == nil || b.cfg.Auth.WorkloadIdentityProvider == "" {
		return nil, fmt.Errorf("GCS OIDC auth requires auth.workload_identity_provider")
	}
	if b.cfg.Auth.ServiceAccount == "" {
		return nil, fmt.Errorf("GCS OIDC auth requires auth.service_account")
	}

	audience := b.cfg.Auth.Audience
	if audience == "" {
		audience = "//iam.googleapis.com/" + b.cfg.Auth.WorkloadIdentityProvider
	}

	// Verify a CI OIDC provider is available before constructing the
	// credential — fail loudly here rather than during the first GCS call.
	if _, err := attestation.ObtainOIDCToken(ctx, audience); err != nil {
		return nil, fmt.Errorf("failed to obtain CI OIDC token for GCS auth: %w", err)
	}

	cfg := externalaccount.Config{
		Audience:                       audience,
		SubjectTokenType:               gcsSubjectTokenType,
		TokenURL:                       gcsSTSTokenURL,
		ServiceAccountImpersonationURL: fmt.Sprintf(gcsImpersonationURLTemplate, b.cfg.Auth.ServiceAccount),
		Scopes:                         []string{storage.ScopeReadWrite},
		SubjectTokenSupplier:           &gcsCISubjectTokenSupplier{audience: audience},
	}

	tokenSource, err := externalaccount.NewTokenSource(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build GCS WIF token source: %w", err)
	}
	return []option.ClientOption{option.WithTokenSource(tokenSource)}, nil
}

// gcsCISubjectTokenSupplier supplies the CI OIDC token as the subject
// token for STS token exchange. It re-fetches the token on every call so
// short-lived tokens stay fresh during long runs.
type gcsCISubjectTokenSupplier struct {
	audience string
}

// SubjectToken implements externalaccount.SubjectTokenSupplier.
func (s *gcsCISubjectTokenSupplier) SubjectToken(ctx context.Context, _ externalaccount.SupplierOptions) (string, error) {
	token, err := attestation.ObtainOIDCToken(ctx, s.audience)
	if err != nil {
		return "", err
	}
	if token == nil || token.Token == "" {
		return "", fmt.Errorf("no CI OIDC token available for GCS auth")
	}
	return token.Token, nil
}

// StoreRaw saves raw data to GCS at the given path.
func (b *GCSBackend) StoreRaw(ctx context.Context, path string, data []byte, metadata map[string]string) (*StoredItem, error) {
	key := buildS3Key(b.cfg.Prefix, path)

	obj := b.client.Bucket(b.cfg.Bucket).Object(key)
	w := obj.NewWriter(ctx)
	w.ContentType = "application/json"
	if len(metadata) > 0 {
		w.Metadata = metadata
	}

	if _, err := w.Write(data); err != nil {
		_ = w.Close() //nolint:errcheck // best-effort cleanup
		return nil, fmt.Errorf("failed to write GCS object: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize GCS object: %w", err)
	}

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
func (b *GCSBackend) List(ctx context.Context, filter *ListFilter) ([]StoredItem, error) {
	prefix := b.cfg.Prefix
	if filter != nil && filter.Prefix != "" {
		prefix = buildS3Key(b.cfg.Prefix, filter.Prefix)
	}

	it := b.client.Bucket(b.cfg.Bucket).Objects(ctx, &storage.Query{Prefix: prefix})

	var items []StoredItem
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list GCS objects: %w", err)
		}

		if filter != nil {
			if !filter.After.IsZero() && attrs.Updated.Before(filter.After) {
				continue
			}
			if !filter.Before.IsZero() && attrs.Updated.After(filter.Before) {
				continue
			}
		}

		items = append(items, StoredItem{
			Path:     attrs.Name,
			Size:     attrs.Size,
			StoredAt: attrs.Updated,
			Hash:     hex.EncodeToString(attrs.MD5),
		})

		if filter != nil && filter.Limit > 0 && len(items) >= filter.Limit {
			return items, nil
		}
	}
	return items, nil
}

// Get retrieves a stored item by path.
func (b *GCSBackend) Get(ctx context.Context, path string) ([]byte, error) {
	key := buildS3Key(b.cfg.Prefix, path)
	r, err := b.client.Bucket(b.cfg.Bucket).Object(key).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, &NotFoundError{Path: path}
		}
		return nil, fmt.Errorf("failed to get GCS object: %w", err)
	}
	defer r.Close() //nolint:errcheck // closing reader, not actionable

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read GCS object: %w", err)
	}
	return data, nil
}

// URIFor returns a gs:// URI for a relative storage path.
func (b *GCSBackend) URIFor(path string) string {
	key := buildS3Key(b.cfg.Prefix, path)
	return "gs://" + b.cfg.Bucket + "/" + key
}

// Close closes the GCS client.
func (b *GCSBackend) Close() error {
	if b.client == nil {
		return nil
	}
	if err := b.client.Close(); err != nil {
		return fmt.Errorf("failed to close GCS client: %w", err)
	}
	return nil
}
