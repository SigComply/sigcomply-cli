package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"

	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
)

// defaultAzureOIDCAudience is the audience expected by Azure AD when
// receiving a federated client assertion.
const defaultAzureOIDCAudience = "api://AzureADTokenExchange"

// AzureBlobBackend implements storage using Azure Blob Storage.
type AzureBlobBackend struct {
	cfg    *AzureBlobConfig
	client *azblob.Client
}

// NewAzureBlobBackend creates a new Azure Blob storage backend.
func NewAzureBlobBackend(cfg *AzureBlobConfig) *AzureBlobBackend {
	return &AzureBlobBackend{cfg: cfg}
}

// Name returns the backend identifier.
func (b *AzureBlobBackend) Name() string { return "azure_blob" }

// Init initializes the Azure Blob backend.
//
// Auth strategy:
//   - nil or Mode "ambient":  azidentity.DefaultAzureCredential
//     (env vars / managed identity / workload identity / az CLI).
//   - Mode "oidc":            ClientAssertionCredential with the CI
//     OIDC token presented as the federated client assertion.
func (b *AzureBlobBackend) Init(ctx context.Context) error {
	cred, err := b.credential(ctx)
	if err != nil {
		return err
	}

	serviceURL := b.serviceURL()
	clientOpts := &azblob.ClientOptions{
		ClientOptions: policy.ClientOptions{},
	}
	client, err := azblob.NewClient(serviceURL, cred, clientOpts)
	if err != nil {
		return fmt.Errorf("failed to create Azure Blob client: %w", err)
	}
	b.client = client

	// Verify container access by reading its properties.
	_, err = b.client.ServiceClient().NewContainerClient(b.cfg.Container).GetProperties(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to access Azure Blob container %s: %w", b.cfg.Container, err)
	}
	return nil
}

// credential builds an azcore.TokenCredential according to the auth mode.
func (b *AzureBlobBackend) credential(ctx context.Context) (azcore.TokenCredential, error) {
	mode := AuthModeAmbient
	if b.cfg.Auth != nil && b.cfg.Auth.Mode != "" {
		mode = b.cfg.Auth.Mode
	}

	switch mode {
	case AuthModeAmbient:
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to load Azure default credential: %w", err)
		}
		return cred, nil

	case AuthModeOIDC:
		return b.oidcCredential(ctx)

	default:
		return nil, fmt.Errorf("unsupported auth mode for Azure Blob backend: %q", b.cfg.Auth.Mode)
	}
}

// oidcCredential builds a ClientAssertionCredential that presents the CI
// OIDC token as the federated client assertion to Azure AD.
func (b *AzureBlobBackend) oidcCredential(ctx context.Context) (azcore.TokenCredential, error) {
	if b.cfg.Auth == nil || b.cfg.Auth.TenantID == "" {
		return nil, fmt.Errorf("OIDC auth for Azure Blob requires auth.tenant_id")
	}
	if b.cfg.Auth.ClientID == "" {
		return nil, fmt.Errorf("OIDC auth for Azure Blob requires auth.client_id")
	}

	audience := b.cfg.Auth.Audience
	if audience == "" {
		audience = defaultAzureOIDCAudience
	}

	// Verify a CI OIDC provider is available before constructing the
	// credential; surfaces a clear error early instead of inside Azure SDK.
	if _, err := attestation.ObtainOIDCToken(ctx, audience); err != nil {
		return nil, fmt.Errorf("failed to obtain CI OIDC token for Azure Blob auth: %w", err)
	}

	getAssertion := func(ctx context.Context) (string, error) {
		token, err := attestation.ObtainOIDCToken(ctx, audience)
		if err != nil {
			return "", err
		}
		if token == nil || token.Token == "" {
			return "", fmt.Errorf("no CI OIDC token available for Azure Blob auth")
		}
		return token.Token, nil
	}

	cred, err := azidentity.NewClientAssertionCredential(
		b.cfg.Auth.TenantID,
		b.cfg.Auth.ClientID,
		getAssertion,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build Azure ClientAssertionCredential: %w", err)
	}
	return cred, nil
}

// serviceURL returns the configured endpoint or the default one for the
// account.
func (b *AzureBlobBackend) serviceURL() string {
	if b.cfg.Endpoint != "" {
		return b.cfg.Endpoint
	}
	return "https://" + b.cfg.Account + ".blob.core.windows.net"
}

// StoreRaw saves raw data to the configured container at the given blob name.
func (b *AzureBlobBackend) StoreRaw(ctx context.Context, path string, data []byte, metadata map[string]string) (*StoredItem, error) {
	key := buildS3Key(b.cfg.Prefix, path)

	// Convert metadata map[string]string -> map[string]*string (Azure form).
	azMetadata := make(map[string]*string, len(metadata))
	for k, v := range metadata {
		v := v
		azMetadata[k] = &v
	}

	contentType := "application/json"
	uploadOpts := &blockblob.UploadBufferOptions{
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType: &contentType,
		},
		Metadata: azMetadata,
	}
	_, err := b.client.UploadBuffer(ctx, b.cfg.Container, key, data, uploadOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to upload Azure Blob: %w", err)
	}

	hash := sha256.Sum256(data)
	return &StoredItem{
		Path:        key,
		Hash:        hex.EncodeToString(hash[:]),
		Size:        int64(len(data)),
		StoredAt:    time.Now().UTC(),
		ContentType: contentType,
		Metadata:    metadata,
	}, nil
}

// List returns blobs matching the filter.
func (b *AzureBlobBackend) List(ctx context.Context, filter *ListFilter) ([]StoredItem, error) {
	prefix := b.cfg.Prefix
	if filter != nil && filter.Prefix != "" {
		prefix = buildS3Key(b.cfg.Prefix, filter.Prefix)
	}

	pager := b.client.NewListBlobsFlatPager(b.cfg.Container, &container.ListBlobsFlatOptions{
		Prefix: &prefix,
	})

	var items []StoredItem
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Azure blobs: %w", err)
		}
		for _, blobItem := range page.Segment.BlobItems {
			item, ok := convertAzureBlobItem(blobItem, filter)
			if !ok {
				continue
			}
			items = append(items, item)
			if filter != nil && filter.Limit > 0 && len(items) >= filter.Limit {
				return items, nil
			}
		}
	}
	return items, nil
}

// convertAzureBlobItem flattens an Azure ListBlobsFlat entry into a
// StoredItem, applying time filters. Returns ok=false when the item should
// be skipped (missing data or filtered out).
func convertAzureBlobItem(item *container.BlobItem, filter *ListFilter) (StoredItem, bool) {
	if item.Name == nil || item.Properties == nil {
		return StoredItem{}, false
	}
	modTime := time.Time{}
	if item.Properties.LastModified != nil {
		modTime = *item.Properties.LastModified
	}
	if filter != nil {
		if !filter.After.IsZero() && modTime.Before(filter.After) {
			return StoredItem{}, false
		}
		if !filter.Before.IsZero() && modTime.After(filter.Before) {
			return StoredItem{}, false
		}
	}
	size := int64(0)
	if item.Properties.ContentLength != nil {
		size = *item.Properties.ContentLength
	}
	hash := ""
	if item.Properties.ContentMD5 != nil {
		hash = hex.EncodeToString(item.Properties.ContentMD5)
	}
	return StoredItem{
		Path:     *item.Name,
		Size:     size,
		StoredAt: modTime,
		Hash:     hash,
	}, true
}

// Get retrieves a stored blob by path.
func (b *AzureBlobBackend) Get(ctx context.Context, path string) ([]byte, error) {
	key := buildS3Key(b.cfg.Prefix, path)

	resp, err := b.client.DownloadStream(ctx, b.cfg.Container, key, nil)
	if err != nil {
		if bloberror.HasCode(err, bloberror.BlobNotFound) {
			return nil, &NotFoundError{Path: path}
		}
		return nil, fmt.Errorf("failed to download Azure Blob: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // closing response body, error not actionable

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read Azure Blob: %w", err)
	}
	return buf.Bytes(), nil
}

// URIFor returns the canonical https URL for a blob (account/container/key).
func (b *AzureBlobBackend) URIFor(path string) string {
	key := buildS3Key(b.cfg.Prefix, path)
	return b.serviceURL() + "/" + b.cfg.Container + "/" + key
}

// Close closes the Azure Blob backend (no-op).
func (b *AzureBlobBackend) Close() error { return nil }
