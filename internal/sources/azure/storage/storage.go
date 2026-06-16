// Package storage implements the azure.storage source plugin: lists every
// Azure Storage account in a subscription and emits one cross-vendor
// object_storage_bucket record per account, so encryption-at-rest,
// public-access, and versioning policies evaluate against Azure exactly as
// they do against AWS S3 and GCS — zero policy changes (Invariant #4,
// substitutability).
//
// Two ARM reads, joined per account:
//   - AccountsClient.NewListPager — the account's Location, CreationTime,
//     Encryption (CMEK vs Microsoft-managed) and AllowBlobPublicAccess.
//   - BlobServicesClient.GetServiceProperties("default") — IsVersioningEnabled
//     and the blob soft-delete retention policy. These live on the blob
//     service, not the account, so each account needs a second GET (N+1); the
//     resource group is parsed from the account's ARM id for that call.
//
// Honest mappings (the plugin owns 100% of the vendor→canonical translation):
//   - encryption_at_rest_enabled is unconditionally true: Azure Storage
//     Service Encryption is always-on and cannot be disabled. kms_managed
//     reflects whether a customer-managed key (CMEK) is used instead.
//   - public_access_blocked is true only when AllowBlobPublicAccess is
//     explicitly false. A nil value (not returned) is treated as NOT provably
//     blocked, so an absent setting never reads as "secure".
//   - versioning_enabled is true when blob versioning OR blob soft-delete is
//     on — the schema field covers both ("object versioning / soft-delete").
//     The granular blob_versioning_enabled / blob_soft_delete_enabled booleans
//     ride in additionalProperties so the derivation stays auditable.
//
// Test injection: the API interface is the single seam; the real adapter
// (realStorage) wraps the armstorage SDK clients and unit tests inject an
// in-memory fake. Real-adapter HTTP behavior is covered with httptest;
// deeper integration coverage is deferred to the testing strategy revamp.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the cross-vendor object_storage_bucket shape. Azure Blob
// is one of several substitutable object-storage sources (AWS S3, GCS).
const EvidenceTypeID = "object_storage_bucket"

// SourceID is the registered ID for the azure.storage plugin instance.
const SourceID = "azure.storage"

// API is the subset of the Azure Storage management plane this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting ARM;
// the real adapter (realStorage) wraps the armstorage SDK clients.
type API interface {
	// ListAccounts returns every storage account in the configured subscription.
	ListAccounts(ctx context.Context) ([]*armstorage.Account, error)
	// GetBlobProperties returns the blob-service properties (versioning,
	// soft-delete) for one account. resourceGroup is parsed from the account's
	// ARM id by the caller.
	GetBlobProperties(ctx context.Context, resourceGroup, account string) (*armstorage.BlobServicePropertiesProperties, error)
}

// Plugin is the in-process azure.storage source.
type Plugin struct {
	api            API
	subscriptionID string
	now            func() time.Time
}

// Options is the constructor input.
type Options struct {
	API            API
	SubscriptionID string
	// Now is injected so tests can produce deterministic CollectedAt values.
	// Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers using
// the real Azure SDK should use NewFromAzure.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:            opts.API,
		subscriptionID: opts.SubscriptionID,
		now:            now,
	}
}

// NewFromAzure constructs a Plugin backed by the real armstorage SDK using the
// given credential (a DefaultAzureCredential) scoped to cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealStorage(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return New(Options{API: adapter, SubscriptionID: cfg.SubscriptionID}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// bucketPayload is the object_storage_bucket shape this plugin emits. The
// required fields (name, encryption_at_rest_enabled, public_access_blocked)
// are always present. The blob_* booleans and Azure posture fields are
// additionalProperties (the schema allows them) that make the
// versioning_enabled derivation and security posture auditable.
type bucketPayload struct {
	Name                    string    `json:"name"`
	RegionOrLocation        string    `json:"region_or_location,omitempty"`
	EncryptionAtRestEnabled bool      `json:"encryption_at_rest_enabled"`
	KMSManaged              bool      `json:"kms_managed,omitempty"`
	KMSKeyID                string    `json:"kms_key_id,omitempty"`
	PublicAccessBlocked     bool      `json:"public_access_blocked"`
	VersioningEnabled       bool      `json:"versioning_enabled,omitempty"`
	CreatedAt               time.Time `json:"created_at,omitempty"`

	// Auditable Azure extras (additionalProperties).
	BlobVersioningEnabled   bool   `json:"blob_versioning_enabled"`
	BlobSoftDeleteEnabled   bool   `json:"blob_soft_delete_enabled"`
	SoftDeleteRetentionDays int32  `json:"soft_delete_retention_days,omitempty"`
	MinimumTLSVersion       string `json:"minimum_tls_version,omitempty"`
	PublicNetworkAccess     string `json:"public_network_access,omitempty"`
}

// Collect lists storage accounts in the configured subscription and emits one
// object_storage_bucket record per account, sorted by ID (account name) so
// envelope bytes are stable across runs against stable state.
//
// A blob-service read failure (e.g. a missing-permission 403) is surfaced as
// an error rather than silently reporting versioning_enabled=false, which
// would be misleading false-fail evidence; the error tags only the
// azure.storage-bound policies `error`, not a run crash.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.storage: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	accounts, err := p.api.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.storage: list accounts: %w", err)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(accounts))
	for _, acc := range accounts {
		if acc == nil {
			continue
		}
		name := deref(acc.Name)
		rg, err := resourceGroupFromID(deref(acc.ID))
		if err != nil {
			return nil, fmt.Errorf("azure.storage: account %q: %w", name, err)
		}
		bp, err := p.api.GetBlobProperties(ctx, rg, name)
		if err != nil {
			return nil, fmt.Errorf("azure.storage: blob properties for %q: %w", name, err)
		}
		versioning, softDelete, retentionDays := versioningSignals(bp)
		enc := encryption(acc)
		payload := bucketPayload{
			Name:                    name,
			RegionOrLocation:        deref(acc.Location),
			EncryptionAtRestEnabled: true, // Azure SSE is always-on; the question is only whether a CMEK is used.
			KMSManaged:              cmekEnabled(enc),
			KMSKeyID:                kmsKeyID(enc),
			PublicAccessBlocked:     publicAccessBlocked(acc),
			VersioningEnabled:       versioning || softDelete,
			CreatedAt:               creationTime(acc),
			BlobVersioningEnabled:   versioning,
			BlobSoftDeleteEnabled:   softDelete,
			SoftDeleteRetentionDays: retentionDays,
			MinimumTLSVersion:       minimumTLSVersion(acc),
			PublicNetworkAccess:     publicNetworkAccess(acc),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("azure.storage: marshal account payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          name,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
			Scope:       scope,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// --- pure mapping helpers (unit-tested via table tests) ---

// resourceGroupFromID extracts the resource group from an ARM resource id of
// the form /subscriptions/{sub}/resourceGroups/{rg}/providers/... . The match
// is case-insensitive because ARM sometimes returns "resourcegroups".
func resourceGroupFromID(id string) (string, error) {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			if rg := parts[i+1]; rg != "" {
				return rg, nil
			}
		}
	}
	return "", fmt.Errorf("no resourceGroups segment in id %q", id)
}

// publicAccessBlocked is true only when AllowBlobPublicAccess is explicitly
// false. A nil value is treated as NOT provably blocked (conservative — an
// absent setting never reads as secure).
func publicAccessBlocked(acc *armstorage.Account) bool {
	if acc == nil || acc.Properties == nil || acc.Properties.AllowBlobPublicAccess == nil {
		return false
	}
	return !*acc.Properties.AllowBlobPublicAccess
}

// encryption returns the account's Encryption block, nil-safe.
func encryption(acc *armstorage.Account) *armstorage.Encryption {
	if acc == nil || acc.Properties == nil {
		return nil
	}
	return acc.Properties.Encryption
}

// cmekEnabled reports whether the account uses a customer-managed key
// (Microsoft.Keyvault) rather than the Microsoft-managed default.
func cmekEnabled(enc *armstorage.Encryption) bool {
	return enc != nil && enc.KeySource != nil && *enc.KeySource == armstorage.KeySourceMicrosoftKeyvault
}

// kmsKeyID returns an identifier for the customer-managed key, or "" when none
// is configured. Prefers the resolved versioned key identifier; otherwise
// composes vault uri + key name + version.
func kmsKeyID(enc *armstorage.Encryption) string {
	if !cmekEnabled(enc) || enc.KeyVaultProperties == nil {
		return ""
	}
	kv := enc.KeyVaultProperties
	if kv.CurrentVersionedKeyIdentifier != nil && *kv.CurrentVersionedKeyIdentifier != "" {
		return *kv.CurrentVersionedKeyIdentifier
	}
	parts := make([]string, 0, 3)
	for _, s := range []*string{kv.KeyVaultURI, kv.KeyName, kv.KeyVersion} {
		if s != nil && *s != "" {
			parts = append(parts, *s)
		}
	}
	return strings.Join(parts, "/")
}

// versioningSignals extracts blob versioning + soft-delete state from the blob
// service properties, all nil-safe.
func versioningSignals(bp *armstorage.BlobServicePropertiesProperties) (versioning, softDelete bool, retentionDays int32) {
	if bp == nil {
		return false, false, 0
	}
	if bp.IsVersioningEnabled != nil {
		versioning = *bp.IsVersioningEnabled
	}
	if d := bp.DeleteRetentionPolicy; d != nil {
		if d.Enabled != nil {
			softDelete = *d.Enabled
		}
		if softDelete && d.Days != nil {
			retentionDays = *d.Days
		}
	}
	return versioning, softDelete, retentionDays
}

func creationTime(acc *armstorage.Account) time.Time {
	if acc == nil || acc.Properties == nil || acc.Properties.CreationTime == nil {
		return time.Time{}
	}
	return acc.Properties.CreationTime.UTC()
}

func minimumTLSVersion(acc *armstorage.Account) string {
	if acc == nil || acc.Properties == nil || acc.Properties.MinimumTLSVersion == nil {
		return ""
	}
	return string(*acc.Properties.MinimumTLSVersion)
}

func publicNetworkAccess(acc *armstorage.Account) string {
	if acc == nil || acc.Properties == nil || acc.Properties.PublicNetworkAccess == nil {
		return ""
	}
	return string(*acc.Properties.PublicNetworkAccess)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- real Azure Storage adapter ---

// realStorage is the production implementation of API. It wraps the armstorage
// AccountsClient (subscription-wide list) and BlobServicesClient (per-account
// versioning / soft-delete).
type realStorage struct {
	accounts *armstorage.AccountsClient
	blob     *armstorage.BlobServicesClient
}

// newRealStorage builds the armstorage clients. opts is nil in production;
// tests pass a *arm.ClientOptions pointing the clients at an httptest server.
func newRealStorage(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realStorage, error) {
	accounts, err := armstorage.NewAccountsClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.storage: accounts client: %w", err)
	}
	blob, err := armstorage.NewBlobServicesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.storage: blob services client: %w", err)
	}
	return &realStorage{accounts: accounts, blob: blob}, nil
}

func (r *realStorage) ListAccounts(ctx context.Context) ([]*armstorage.Account, error) {
	var out []*armstorage.Account
	pager := r.accounts.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realStorage) GetBlobProperties(ctx context.Context, resourceGroup, account string) (*armstorage.BlobServicePropertiesProperties, error) {
	resp, err := r.blob.GetServiceProperties(ctx, resourceGroup, account, nil)
	if err != nil {
		return nil, err
	}
	return resp.BlobServiceProperties.BlobServiceProperties, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
